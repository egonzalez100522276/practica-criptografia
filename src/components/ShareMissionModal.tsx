import { useState } from 'react';
import { X, Send, Users } from 'lucide-react';
import { Mission } from '../types';

interface ShareMissionModalProps {
  mission: Mission;
  onClose: () => void;
  onShare: (agentId: string, message: string) => void;
}

export default function ShareMissionModal({ mission, onClose, onShare }: ShareMissionModalProps) {
  const [selectedAgent, setSelectedAgent] = useState('');
  const [message, setMessage] = useState('');

  const availableAgents = [
    { id: 'agent-001', name: 'Agent Shadow', status: 'online' },
    { id: 'agent-002', name: 'Agent Phantom', status: 'offline' },
    { id: 'agent-003', name: 'Agent Viper', status: 'online' },
    { id: 'agent-004', name: 'Agent Raven', status: 'online' },
  ];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedAgent && message.trim()) {
      onShare(selectedAgent, message);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
      <div className="bg-slate-800 rounded-2xl shadow-2xl border border-slate-700 w-full max-w-lg animate-scale-in">
        <div className="flex items-center justify-between p-6 border-b border-slate-700">
          <div className="flex items-center space-x-3">
            <div className="bg-gradient-to-br from-red-600 to-orange-600 rounded-lg p-2">
              <Send className="w-5 h-5 text-white" />
            </div>
            <h2 className="text-xl font-bold text-white">Share Mission</h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        <div className="p-6">
          <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-4 mb-6">
            <h3 className="text-white font-semibold mb-1">{mission.title}</h3>
            <p className="text-slate-400 text-sm">{mission.description}</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label htmlFor="agent-select" className="block text-sm font-medium text-slate-300 mb-2">
                Select Agent
              </label>
              <div className="relative">
                <Users className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-500 pointer-events-none" />
                <select
                  id="agent-select"
                  value={selectedAgent}
                  onChange={(e) => setSelectedAgent(e.target.value)}
                  className="w-full bg-slate-900/50 border border-slate-700 rounded-lg pl-11 pr-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-red-600 focus:border-transparent transition appearance-none"
                  required
                >
                  <option value="">Choose an agent...</option>
                  {availableAgents.map((agent) => (
                    <option key={agent.id} value={agent.id}>
                      {agent.name} ({agent.status})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label htmlFor="share-message" className="block text-sm font-medium text-slate-300 mb-2">
                Encrypted Message
              </label>
              <textarea
                id="share-message"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Add a classified message for the agent..."
                rows={4}
                className="w-full bg-slate-900/50 border border-slate-700 rounded-lg px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-red-600 focus:border-transparent transition resize-none"
                required
              />
            </div>

            <div className="flex space-x-3 pt-4">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 bg-slate-700 hover:bg-slate-600 text-white font-semibold py-3 rounded-lg transition"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="flex-1 bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-700 hover:to-orange-700 text-white font-semibold py-3 rounded-lg transition shadow-lg shadow-red-600/30 flex items-center justify-center space-x-2"
              >
                <Send className="w-4 h-4" />
                <span>Send Mission</span>
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
