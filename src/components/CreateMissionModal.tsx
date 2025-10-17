import { useState } from 'react';
import { X, FileText } from 'lucide-react';

interface CreateMissionModalProps {
  onClose: () => void;
  onCreate: (title: string, description: string) => void;
}

export default function CreateMissionModal({ onClose, onCreate }: CreateMissionModalProps) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (title.trim() && description.trim()) {
      onCreate(title, description);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
      <div className="bg-slate-800 rounded-2xl shadow-2xl border border-slate-700 w-full max-w-lg animate-scale-in">
        <div className="flex items-center justify-between p-6 border-b border-slate-700">
          <div className="flex items-center space-x-3">
            <div className="bg-gradient-to-br from-red-600 to-orange-600 rounded-lg p-2">
              <FileText className="w-5 h-5 text-white" />
            </div>
            <h2 className="text-xl font-bold text-white">Create New Mission</h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          <div>
            <label htmlFor="mission-title" className="block text-sm font-medium text-slate-300 mb-2">
              Mission Title
            </label>
            <input
              id="mission-title"
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g., Infiltrate Enemy Headquarters"
              className="w-full bg-slate-900/50 border border-slate-700 rounded-lg px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-red-600 focus:border-transparent transition"
              required
            />
          </div>

          <div>
            <label htmlFor="mission-description" className="block text-sm font-medium text-slate-300 mb-2">
              Mission Description
            </label>
            <textarea
              id="mission-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Detailed mission briefing..."
              rows={5}
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
              className="flex-1 bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-700 hover:to-orange-700 text-white font-semibold py-3 rounded-lg transition shadow-lg shadow-red-600/30"
            >
              Create Mission
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
