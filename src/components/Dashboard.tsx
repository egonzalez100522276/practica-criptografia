import { useState } from 'react';
import { CheckCircle2, Circle, Clock, LogOut, Plus, Send, Shield, Target, Users } from 'lucide-react';
import { User, Mission } from '../types';
import CreateMissionModal from './CreateMissionModal';
import ShareMissionModal from './ShareMissionModal';

interface DashboardProps {
  user: User;
  onLogout: () => void;
  onSwitchToAdmin: () => void;
}

export default function Dashboard({ user, onLogout, onSwitchToAdmin }: DashboardProps) {
  const [missions, setMissions] = useState<Mission[]>([
    {
      id: '1',
      title: 'Infiltrate Enemy Base',
      description: 'Gather intelligence from the underground facility without being detected.',
      status: 'pending',
      createdBy: user.id,
      assignedTo: user.id,
      createdAt: new Date().toISOString(),
    },
    {
      id: '2',
      title: 'Decode Encrypted Message',
      description: 'Use cipher key Alpha-7 to decrypt the intercepted communications.',
      status: 'completed',
      createdBy: 'other-agent',
      assignedTo: user.id,
      createdAt: new Date(Date.now() - 86400000).toISOString(),
      completedAt: new Date().toISOString(),
    },
  ]);

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showShareModal, setShowShareModal] = useState(false);
  const [selectedMissionId, setSelectedMissionId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'my' | 'received'>('my');

  const myMissions = missions.filter(m => m.createdBy === user.id);
  const receivedMissions = missions.filter(m => m.createdBy !== user.id && m.assignedTo === user.id);

  const handleToggleMission = (missionId: string) => {
    setMissions(missions.map(m =>
      m.id === missionId
        ? { ...m, status: m.status === 'pending' ? 'completed' : 'pending', completedAt: m.status === 'pending' ? new Date().toISOString() : undefined }
        : m
    ));
  };

  const handleCreateMission = (title: string, description: string) => {
    const newMission: Mission = {
      id: Date.now().toString(),
      title,
      description,
      status: 'pending',
      createdBy: user.id,
      assignedTo: user.id,
      createdAt: new Date().toISOString(),
    };
    setMissions([newMission, ...missions]);
    setShowCreateModal(false);
  };

  const handleShareMission = (missionId: string) => {
    setSelectedMissionId(missionId);
    setShowShareModal(true);
  };

  const displayedMissions = activeTab === 'my' ? myMissions : receivedMissions;

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
                  <p className="text-sm font-semibold text-white">{user.username}</p>
                  <p className="text-xs text-slate-400">{user.role === 'admin' ? 'Administrator' : 'Field Agent'}</p>
                </div>
              </div>

              {user.role === 'admin' && (
                <button
                  onClick={onSwitchToAdmin}
                  className="bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg transition flex items-center space-x-2"
                >
                  <Users className="w-4 h-4" />
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
            <h2 className="text-3xl font-bold text-white mb-2">Active Missions</h2>
            <p className="text-slate-400">Classified operations and assignments</p>
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
              onClick={() => setActiveTab('my')}
              className={`flex-1 px-6 py-4 text-sm font-semibold transition ${
                activeTab === 'my'
                  ? 'bg-red-600 text-white'
                  : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
              }`}
            >
              <div className="flex items-center justify-center space-x-2">
                <Target className="w-4 h-4" />
                <span>My Missions</span>
                <span className="bg-slate-900/50 px-2 py-0.5 rounded-full text-xs">{myMissions.length}</span>
              </div>
            </button>
            <button
              onClick={() => setActiveTab('received')}
              className={`flex-1 px-6 py-4 text-sm font-semibold transition ${
                activeTab === 'received'
                  ? 'bg-red-600 text-white'
                  : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
              }`}
            >
              <div className="flex items-center justify-center space-x-2">
                <Send className="w-4 h-4" />
                <span>Received Missions</span>
                <span className="bg-slate-900/50 px-2 py-0.5 rounded-full text-xs">{receivedMissions.length}</span>
              </div>
            </button>
          </div>

          <div className="p-6">
            {displayedMissions.length === 0 ? (
              <div className="text-center py-12">
                <Clock className="w-16 h-16 text-slate-600 mx-auto mb-4" />
                <p className="text-slate-400 text-lg">No missions in this category</p>
                <p className="text-slate-500 text-sm mt-2">Create a new mission to get started</p>
              </div>
            ) : (
              <div className="space-y-4">
                {displayedMissions.map((mission) => (
                  <div
                    key={mission.id}
                    className={`bg-slate-900/50 border rounded-xl p-6 transition-all hover:border-red-600/50 ${
                      mission.status === 'completed' ? 'border-green-600/30' : 'border-slate-700/50'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-start space-x-4">
                          <button
                            onClick={() => handleToggleMission(mission.id)}
                            className="mt-1 focus:outline-none group"
                          >
                            {mission.status === 'completed' ? (
                              <CheckCircle2 className="w-6 h-6 text-green-500 group-hover:scale-110 transition-transform" />
                            ) : (
                              <Circle className="w-6 h-6 text-slate-500 group-hover:text-red-500 transition" />
                            )}
                          </button>

                          <div className="flex-1">
                            <h3 className={`text-lg font-semibold mb-2 ${
                              mission.status === 'completed' ? 'text-slate-400 line-through' : 'text-white'
                            }`}>
                              {mission.title}
                            </h3>
                            <p className={`text-sm mb-3 ${
                              mission.status === 'completed' ? 'text-slate-500' : 'text-slate-300'
                            }`}>
                              {mission.description}
                            </p>

                            <div className="flex flex-wrap items-center gap-3 text-xs">
                              <span className={`px-3 py-1 rounded-full font-medium ${
                                mission.status === 'completed'
                                  ? 'bg-green-600/20 text-green-400 border border-green-600/30'
                                  : 'bg-orange-600/20 text-orange-400 border border-orange-600/30'
                              }`}>
                                {mission.status === 'completed' ? 'Completed' : 'Pending'}
                              </span>

                              <span className="text-slate-500">
                                Created {new Date(mission.createdAt).toLocaleDateString()}
                              </span>

                              {mission.completedAt && (
                                <span className="text-slate-500">
                                  Completed {new Date(mission.completedAt).toLocaleDateString()}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>

                      {activeTab === 'my' && (
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
          mission={missions.find(m => m.id === selectedMissionId)!}
          onClose={() => {
            setShowShareModal(false);
            setSelectedMissionId(null);
          }}
          onShare={() => {
            setShowShareModal(false);
            setSelectedMissionId(null);
          }}
        />
      )}
    </div>
  );
}
