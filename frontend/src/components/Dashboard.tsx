import { useState, useEffect } from "react";
import {
  CheckCircle2,
  ChevronDown,
  Circle,
  LogOut,
  Plus,
  Send,
  Shield,
  Target,
  User as UserIcon,
} from "lucide-react";
import { User, Mission } from "../types";
import CreateMissionModal from "./CreateMissionModal";
import ShareMissionModal from "./ShareMissionModal";

interface DashboardProps {
  user: User;
  onLogout: () => void;
  token: string | null;
  onSwitchToAdmin: () => void;
  showNotification: (type: "success" | "error", message: string) => void;
  privateKeyPem: string | null;
  sessionPassword: string | null;
}

export default function Dashboard({
  user,
  onLogout,
  onSwitchToAdmin,
  token,
  showNotification,
  privateKeyPem,
  sessionPassword,
}: DashboardProps) {
  const [myMissions, setMyMissions] = useState<Mission[]>([]);
  const [receivedMissions, setReceivedMissions] = useState<Mission[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showShareModal, setShowShareModal] = useState(false);
  const [selectedMissionId, setSelectedMissionId] = useState<string | null>(
    null
  );
  const [activeTab, setActiveTab] = useState<"my" | "received">("my");
  const [loading, setLoading] = useState(false);

  // --- Fetch missions with timer ---
  useEffect(() => {
    if (!token || !privateKeyPem) {
      showNotification("error", "Session data is missing. Please log in again.");
      onLogout();
      return;
    }

    const fetchAllMissions = async () => {
      setLoading(true);

      const fetchEndpoint = async (
        endpoint: string,
        setter: React.Dispatch<React.SetStateAction<Mission[]>>
      ) => {
        try {
          const response = await fetch(`http://127.0.0.1:8000/missions${endpoint}`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({ private_key_pem: privateKeyPem }),
          });

          if (response.ok) {
            const data = await response.json();
            const missions: Mission[] = data.map((m: any) => ({
              id: m.id.toString(),
              title: m.content.title,
              description: m.content.description,
              createdBy: m.creator_username || m.creator_id.toString(),
              assignedTo: user.id.toString(),
              createdAt: new Date().toISOString(),
            }));
            setter(missions);
          } else {
            showNotification("error", `Failed to fetch missions from ${endpoint}.`);
          }
        } catch (err) {
          showNotification("error", `Could not connect to server for ${endpoint}.`);
        }
      };

      await Promise.all([
        fetchEndpoint("/mine/decrypt", setMyMissions),
        fetchEndpoint("/shared/decrypt", setReceivedMissions),
      ]);
      setLoading(false);
    };

    // Initial fetch
    fetchAllMissions();

    // Timer fetch every 30 seconds
    const intervalId = setInterval(fetchAllMissions, 30_000);
    return () => clearInterval(intervalId); // Cleanup
  }, [token, privateKeyPem]); // Only rerun if token or key changes

  // --- Create mission ---
  const handleCreateMission = async (title: string, description: string) => {
    if (!token) {
      showNotification("error", "Authentication error. Please log in again.");
      return;
    }
    const sessionPassword = sessionStorage.getItem("session_password");
    if (!sessionPassword) {
      showNotification("error", "Password not available. Please refresh and login again.");
      return;
    }

    const missionContent = {
      password: sessionPassword,
      content: { title, description },
    };

    try {
      const response = await fetch("http://127.0.0.1:8000/missions/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(missionContent),
      });

      if (response.ok) {
        const newMissionData = await response.json();
        const newMission: Mission = {
          id: newMissionData.id.toString(),
          title: newMissionData.content.title,
          description: newMissionData.content.description,
          createdBy: newMissionData.creator_id.toString(),
          assignedTo: newMissionData.creator_id.toString(),
          createdAt: new Date().toISOString(),
        };
        setMyMissions([newMission, ...myMissions]);
        setShowCreateModal(false);
        showNotification("success", "Mission created successfully!");
      } else {
        const errorData = await response.json();
        let errorMessage = "Failed to create mission.";
        if (Array.isArray(errorData.detail)) {
          errorMessage = `Validation Error: ${errorData.detail[0].msg}`;
        } else if (typeof errorData.detail === "string") {
          errorMessage = `Failed to create mission: ${errorData.detail}`;
        }
        showNotification("error", errorMessage);
      }
    } catch (error) {
      showNotification("error", "Could not connect to the server.");
      console.error("Error creating mission:", error);
    }
  };

  const handleShareMission = (missionId: string) => {
    setSelectedMissionId(missionId);
    setShowShareModal(true);
  };

  const displayedMissions = activeTab === "my" ? myMissions : receivedMissions;

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-slate-900 to-gray-800">
      <header className="bg-slate-800/50 backdrop-blur-lg border-b border-slate-700/50 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="bg-gradient-to-br from-red-600 to-orange-600 rounded-lg p-2">
                <Target className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">Spy Agency</h1>
                <p className="text-xs text-slate-400">Mission Control</p>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <div className="hidden sm:flex items-center space-x-3 bg-slate-900/50 rounded-lg px-4 py-2 border border-slate-700/50">
                <Shield className="w-5 h-5 text-red-500" />
                <div>
                  <p className="text-sm font-semibold text-white">
                    {user.username}
                  </p>
                  <p className="text-xs text-slate-400">
                    {user.role === "leader" ? "Agency leader" : "Field Agent"}
                  </p>
                </div>
              </div>

              {user.role === "leader" && (
                <button
                  onClick={onSwitchToAdmin}
                  className="bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg transition flex items-center space-x-2"
                >
                  <UserIcon className="w-4 h-4" />
                  <span className="hidden sm:inline">Admin Panel</span>
                </button>
              )}

              <button
                onClick={onLogout}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition flex items-center space-x-2"
              >
                <LogOut className="w-4 h-4" />
                <span className="hidden sm:inline">Logout</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-8 space-y-4 sm:space-y-0">
          <div>
            <h2 className="text-3xl font-bold text-white mb-2">
              Active Missions
            </h2>
            <p className="text-slate-400">
              Classified operations and assignments
            </p>
          </div>

          <button
            onClick={() => setShowCreateModal(true)}
            className="bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-700 hover:to-orange-700 text-white px-6 py-3 rounded-lg transition shadow-lg shadow-red-600/30 flex items-center space-x-2 font-semibold"
          >
            <Plus className="w-5 h-5" />
            <span>New Mission</span>
          </button>
        </div>

        <div className="bg-slate-800/50 backdrop-blur-lg rounded-xl border border-slate-700/50 overflow-hidden">
          <div className="flex border-b border-slate-700/50">
            <button
              onClick={() => setActiveTab("my")}
              className={`flex-1 px-6 py-4 text-sm font-semibold transition ${
                activeTab === "my"
                  ? "bg-red-600 text-white"
                  : "text-slate-400 hover:text-white hover:bg-slate-700/50"
              }`}
            >
              <div className="flex items-center justify-center space-x-2">
                <Target className="w-4 h-4" />
                <span>My Missions</span>
                <span className="bg-slate-900/50 px-2 py-0.5 rounded-full text-xs">
                  {myMissions.length}
                </span>
              </div>
            </button>
            <button
              onClick={() => setActiveTab("received")}
              className={`flex-1 px-6 py-4 text-sm font-semibold transition ${
                activeTab === "received"
                  ? "bg-red-600 text-white"
                  : "text-slate-400 hover:text-white hover:bg-slate-700/50"
              }`}
            >
              <div className="flex items-center justify-center space-x-2">
                <Send className="w-4 h-4" />
                <span>Received Missions</span>
                <span className="bg-slate-900/50 px-2 py-0.5 rounded-full text-xs">
                  {receivedMissions.length}
                </span>
              </div>
            </button>
          </div>

          <div className="p-6">
            {loading ? (
              <div className="text-center py-12 text-slate-400">Loading missions...</div>
            ) : displayedMissions.length === 0 ? (
              <div className="text-center py-12">
                <p className="text-slate-400 text-lg">
                  No missions in this category
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {displayedMissions.map((mission) => (
                  <div
                    key={mission.id}
                    className="bg-slate-900/50 border border-slate-700/50 rounded-xl p-6 transition-all hover:border-red-600/50"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-start">
                          <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                              <h3 className="text-lg font-semibold text-white">
                                {mission.title}
                              </h3>
                              {mission.signatureValid !== undefined && (
                                <span
                                  className={`text-xs px-2 py-1 rounded-full border ${
                                    mission.signatureValid
                                      ? "bg-green-600/20 text-green-100 border-green-500/40"
                                      : "bg-red-700/20 text-red-100 border-red-500/40"
                                  }`}
                                >
                                  {mission.signatureValid
                                    ? "Firma válida"
                                    : "Firma no válida"}
                                </span>
                              )}
                            </div>
                            <p className="text-sm mb-3 text-slate-300">
                              {mission.description}
                            </p>

                            <div className="flex flex-wrap items-center gap-3 text-xs">
                              {activeTab === "received" ? (
                                <span className="text-slate-500">
                                  From:{" "}
                                  <span className="font-semibold text-slate-400">
                                    {mission.createdBy}
                                  </span>
                                </span>
                              ) : (
                                <span className="text-slate-500">
                                  Created{" "}
                                  {new Date(
                                    mission.createdAt
                                  ).toLocaleDateString()}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>

                      {activeTab === "my" && (
                        <button
                          onClick={() => handleShareMission(mission.id)}
                          className="ml-4 bg-slate-700 hover:bg-slate-600 text-white p-2 rounded-lg transition"
                        >
                          <Send className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </main>

      {showCreateModal && (
        <CreateMissionModal
          onClose={() => setShowCreateModal(false)}
          onCreate={handleCreateMission}
        />
      )}

      {showShareModal && selectedMissionId && (
        <ShareMissionModal
          mission={myMissions.find((m) => m.id === selectedMissionId)!}
          currentUser={user}
          token={token}
          privateKeyPem={privateKeyPem}
          showNotification={showNotification}
          onClose={() => {
            setShowShareModal(false);
            setSelectedMissionId(null);
          }}
          onShare={(selectedUserIds) => {
            setShowShareModal(false);
            console.log("Sharing mission with users:", selectedUserIds);
            setSelectedMissionId(null);
          }}
        />
      )}
    </div>
  );
}
