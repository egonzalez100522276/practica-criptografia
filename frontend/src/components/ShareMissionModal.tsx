import { useState, useEffect } from "react";
import { Mission, User } from "../types";
import { X, Search } from "lucide-react";

interface ShareMissionModalProps {
  mission: Mission;
  onClose: () => void;
  onShare: (selectedUserIds: string[]) => void;
  token: string | null;
  showNotification: (type: "success" | "error", message: string) => void;
  privateKeyPem: string | null;
  currentUser: User;
}

export default function ShareMissionModal({
  mission,
  onClose,
  onShare,
  token,
  showNotification,
  privateKeyPem,
  currentUser,
}: ShareMissionModalProps) {
  const [users, setUsers] = useState<User[]>([]);
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    const fetchUsers = async () => {
      if (!token) {
        showNotification("error", "Authentication token is missing.");
        return;
      }
      try {
        const response = await fetch("http://127.0.0.1:8000/users/", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (response.ok) {
          const allUsers: User[] = await response.json();
          // Filter out the current user from the list
          const otherUsers = allUsers.filter((u) => u.id !== currentUser.id);
          setUsers(otherUsers);
        } else {
          showNotification("error", "Failed to fetch users.");
        }
      } catch (error) {
        showNotification(
          "error",
          "Could not connect to the server to fetch users."
        );
      }
    };

    fetchUsers();
  }, [token, showNotification, currentUser.id]);

  const handleToggleUser = (userId: string) => {
    setSelectedUserIds((prev) =>
      prev.includes(userId)
        ? prev.filter((id) => id !== userId)
        : [...prev, userId]
    );
  };

  const filteredUsers = users.filter((user) =>
    user.username.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-slate-800 border border-slate-700 rounded-xl shadow-lg w-full max-w-md p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-bold text-white">
            Share Mission: "{mission.title}"
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X />
          </button>
        </div>

        <div className="relative mb-4">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-500" />
          <input
            type="text"
            placeholder="Search agents..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-900/50 border border-slate-700 rounded-lg pl-11 pr-4 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-red-600"
          />
        </div>

        <div className="space-y-2 max-h-60 overflow-y-auto pr-2">
          {filteredUsers.map((user) => (
            <div
              key={user.id}
              onClick={() => handleToggleUser(user.id.toString())}
              className={`flex items-center justify-between p-3 rounded-lg cursor-pointer transition ${
                selectedUserIds.includes(user.id.toString())
                  ? "bg-red-600/20 border border-red-500"
                  : "bg-slate-700/50 hover:bg-slate-700"
              }`}
            >
              <span className="text-white font-medium">{user.username}</span>
              <span className="text-xs text-slate-400">{user.role}</span>
            </div>
          ))}
        </div>

        <div className="mt-6 flex justify-end space-x-4">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-white transition"
          >
            Cancel
          </button>
          <button
            onClick={async () => {
              if (!token || !privateKeyPem) {
                showNotification(
                  "error",
                  "Session data is missing. Please log in again."
                );
                return;
              }

              try {
                const response = await fetch(
                  `http://127.0.0.1:8000/missions/${mission.id}/share`,
                  {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                      Authorization: `Bearer ${token}`,
                    },
                    body: JSON.stringify({
                      user_ids: selectedUserIds.map((id) => parseInt(id, 10)),
                      private_key_pem: privateKeyPem,
                    }),
                  }
                );

                if (response.ok) {
                  const result = await response.json();
                  showNotification("success", result.message);
                  onShare(selectedUserIds);
                } else {
                  const errorData = await response.json();
                  showNotification(
                    "error",
                    `Failed to share: ${errorData.detail}`
                  );
                }
              } catch (error) {
                showNotification(
                  "error",
                  "Could not connect to the server to share mission."
                );
              }
            }}
            disabled={selectedUserIds.length === 0}
            className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white font-semibold transition disabled:bg-slate-600 disabled:cursor-not-allowed"
          >
            Share
          </button>
        </div>
      </div>
    </div>
  );
}
