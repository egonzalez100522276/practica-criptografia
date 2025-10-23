import { useState } from "react";
import { ArrowLeft, Filter, Search, Shield, User } from "lucide-react";
import { User as UserType, Mission } from "../types";

interface AdminPanelProps {
  user: UserType;
  onBack: () => void;
}

export default function AdminPanel({ user, onBack }: AdminPanelProps) {
  const allMissions: Mission[] = [
    {
      id: "1",
      title: "Infiltrate Enemy Base",
      description:
        "Gather intelligence from the underground facility without being detected.",
      createdBy: "agent-001",
      assignedTo: "agent-001",
      createdAt: new Date().toISOString(),
    },
    {
      id: "2",
      title: "Decode Encrypted Message",
      description:
        "Use cipher key Alpha-7 to decrypt the intercepted communications.",
      createdBy: "agent-002",
      assignedTo: "agent-001",
      createdAt: new Date(Date.now() - 86400000).toISOString(),
    },
    {
      id: "3",
      title: "Surveil Target Location",
      description:
        "Monitor the warehouse for 72 hours and report all movements.",
      createdBy: "agent-003",
      assignedTo: "agent-003",
      createdAt: new Date(Date.now() - 172800000).toISOString(),
    },
  ];

  const agents = [
    { id: "agent-001", name: "Agent Shadow" },
    { id: "agent-002", name: "Agent Phantom" },
    { id: "agent-003", name: "Agent Viper" },
    { id: "agent-004", name: "Agent Raven" },
  ];

  const [searchTerm, setSearchTerm] = useState("");
  const [filterAgent, setFilterAgent] = useState("all");

  const getAgentName = (agentId: string) => {
    return agents.find((a) => a.id === agentId)?.name || agentId;
  };

  const filteredMissions = allMissions.filter((mission) => {
    const matchesSearch =
      mission.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      mission.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesAgent =
      filterAgent === "all" ||
      mission.createdBy === filterAgent ||
      mission.assignedTo === filterAgent;

    return matchesSearch && matchesAgent;
  });

  const stats = {
    total: allMissions.length,
    agents: agents.length,
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-slate-900 to-gray-800">
      <header className="bg-slate-800/50 backdrop-blur-lg border-b border-slate-700/50 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <button
                onClick={onBack}
                className="bg-slate-700 hover:bg-slate-600 text-white p-2 rounded-lg transition"
              >
                <ArrowLeft className="w-5 h-5" />
              </button>
              <div className="bg-gradient-to-br from-red-600 to-orange-600 rounded-lg p-2">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">
                  Admin Control Panel
                </h1>
                <p className="text-xs text-slate-400">All Agency Operations</p>
              </div>
            </div>

            <div className="flex items-center space-x-3 bg-slate-900/50 rounded-lg px-4 py-2 border border-slate-700/50">
              <Shield className="w-5 h-5 text-red-500" />
              <div>
                <p className="text-sm font-semibold text-white">
                  {user.username}
                </p>
                <p className="text-xs text-slate-400">Administrator</p>
              </div>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-8">
          <div className="bg-slate-800/50 backdrop-blur-lg rounded-xl border border-slate-700/50 p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm font-medium">
                  Total Missions
                </p>
                <p className="text-3xl font-bold text-white mt-2">
                  {stats.total}
                </p>
              </div>
              <div className="bg-gradient-to-br from-red-600 to-orange-600 rounded-lg p-3">
                <Shield className="w-6 h-6 text-white" />
              </div>
            </div>
          </div>

          <div className="bg-slate-800/50 backdrop-blur-lg rounded-xl border border-slate-700/50 p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm font-medium">
                  Active Agents
                </p>
                <p className="text-3xl font-bold text-white mt-2">
                  {stats.agents}
                </p>
              </div>
              <div className="bg-slate-700 rounded-lg p-3">
                <User className="w-6 h-6 text-white" />
              </div>
            </div>
          </div>
        </div>

        <div className="bg-slate-800/50 backdrop-blur-lg rounded-xl border border-slate-700/50 overflow-hidden">
          <div className="p-6 border-b border-slate-700/50">
            <h2 className="text-xl font-bold text-white mb-4">All Missions</h2>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-500" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search missions..."
                  className="w-full bg-slate-900/50 border border-slate-700 rounded-lg pl-11 pr-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-red-600 focus:border-transparent transition"
                />
              </div>

              <div className="relative">
                <Filter className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-500" />
                <select
                  value={filterAgent}
                  onChange={(e) => setFilterAgent(e.target.value)}
                  className="w-full bg-slate-900/50 border border-slate-700 rounded-lg pl-11 pr-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-red-600 focus:border-transparent transition appearance-none"
                >
                  <option value="all">All Agents</option>
                  {agents.map((agent) => (
                    <option key={agent.id} value={agent.id}>
                      {agent.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-900/50">
                <tr>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Mission
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider hidden lg:table-cell">
                    Created By
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider hidden lg:table-cell">
                    Assigned To
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider hidden sm:table-cell">
                    Date
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {filteredMissions.length === 0 ? (
                  <tr>
                    <td
                      colSpan={5}
                      className="px-6 py-12 text-center text-slate-400"
                    >
                      No missions found matching your filters
                    </td>
                  </tr>
                ) : (
                  filteredMissions.map((mission) => (
                    <tr
                      key={mission.id}
                      className="hover:bg-slate-700/30 transition"
                    >
                      <td className="px-6 py-4">
                        <div>
                          <p className="text-white font-medium">
                            {mission.title}
                          </p>
                          <p className="text-slate-400 text-sm mt-1 line-clamp-1">
                            {mission.description}
                          </p>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-slate-300 text-sm hidden lg:table-cell">
                        {getAgentName(mission.createdBy)}
                      </td>
                      <td className="px-6 py-4 text-slate-300 text-sm hidden lg:table-cell">
                        {getAgentName(mission.assignedTo)}
                      </td>
                      <td className="px-6 py-4 text-slate-400 text-sm hidden sm:table-cell">
                        {new Date(mission.createdAt).toLocaleDateString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  );
}
