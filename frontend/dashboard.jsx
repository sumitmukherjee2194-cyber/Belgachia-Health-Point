const { useState, useEffect } = React;

function Dashboard() {
  const [insights, setInsights] = useState([]);
  const [query, setQuery] = useState('');
  const [response, setResponse] = useState('');

  const fetchInsights = async () => {
    const res = await fetch('/generate-insight', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data_period: 'weekly', data_scope: 'pharmacy' })
    });
    const data = await res.json();
    setInsights(data.recommendations || []);
  };

  const handleQuery = async () => {
    const res = await fetch('/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query_text: query })
    });
    const data = await res.json();
    setResponse(data.answer || '');
  };

  useEffect(() => { fetchInsights(); }, []);

  return (
    <div className='p-6 bg-gray-100 min-h-screen'>
      <h1 className='text-2xl font-bold mb-4 text-blue-800'>Belgachia Health Point Billing AI</h1>

      <div className='grid grid-cols-1 md:grid-cols-3 gap-4 mb-6'>
        <div className='bg-white p-4 rounded-2xl shadow'><h2 className='text-lg font-semibold text-gray-700'>Total Revenue</h2><p className='text-2xl font-bold text-green-600'>₹8,42,500</p></div>
        <div className='bg-white p-4 rounded-2xl shadow'><h2 className='text-lg font-semibold text-gray-700'>Outstanding Dues</h2><p className='text-2xl font-bold text-red-500'>₹1,12,000</p></div>
        <div className='bg-white p-4 rounded-2xl shadow'><h2 className='text-lg font-semibold text-gray-700'>Pending Claims</h2><p className='text-2xl font-bold text-yellow-600'>₹76,000</p></div>
      </div>

      <div className='bg-white p-4 rounded-2xl shadow mb-6'>
        <h2 className='font-semibold text-gray-800 mb-2'>AI Insights</h2>
        <ul className='list-disc ml-6 text-gray-700'>
          {insights.map((i, idx) => <li key={idx}>{i}</li>)}
        </ul>
      </div>

      <div className='bg-white p-4 rounded-2xl shadow'>
        <h2 className='font-semibold text-gray-800 mb-2'>Ask AI Assistant</h2>
        <div className='flex gap-2'>
          <input className='border p-2 flex-1 rounded' placeholder='e.g. Show unpaid bills above ₹10,000' value={query} onChange={(e)=>setQuery(e.target.value)} />
          <button onClick={handleQuery} className='bg-blue-600 text-white px-4 py-2 rounded'>Ask</button>
        </div>
        {response && <p className='mt-3 text-gray-700'>{response}</p>}
      </div>
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<Dashboard />);
