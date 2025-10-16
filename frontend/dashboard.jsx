const { useState, useEffect } = React;

function Dashboard() {
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const [role, setRole] = useState(localStorage.getItem('role') || '');
  const [username, setUsername] = useState(localStorage.getItem('username') || '');

  const [loginUsername, setLoginUsername] = useState('admin');
  const [loginPassword, setLoginPassword] = useState('admin123');
  const [loginError, setLoginError] = useState('');

  const [insights, setInsights] = useState([]);
  const [query, setQuery] = useState('');
  const [response, setResponse] = useState('');

  const [file, setFile] = useState(null);
  const [dataType, setDataType] = useState('billing');
  const [uploadResult, setUploadResult] = useState(null);
  const [analytics, setAnalytics] = useState(null);
  const [anomalySummary, setAnomalySummary] = useState(null);
  const chartsRef = React.useRef({});

  const authHeaders = () => token ? { 'Authorization': `Bearer ${token}` } : {};

  const doLogin = async () => {
    setLoginError('');
    try {
      const res = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: loginUsername, password: loginPassword })
      });
      if (!res.ok) throw new Error('Login failed');
      const data = await res.json();
      localStorage.setItem('token', data.access_token);
      localStorage.setItem('role', data.role);
      localStorage.setItem('username', data.username);
      setToken(data.access_token);
      setRole(data.role);
      setUsername(data.username);
      await Promise.all([fetchInsights(), fetchAnalytics()]);
    } catch (e) {
      setLoginError('Invalid credentials');
    }
  };

  const doLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    localStorage.removeItem('username');
    setToken('');
    setRole('');
    setUsername('');
    setInsights([]);
    setAnalytics(null);
    setResponse('');
  };

  const fetchInsights = async () => {
    if (!token) return;
    const res = await fetch('/generate-insight', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ data_period: 'weekly', data_scope: 'pharmacy' })
    });
    const data = await res.json();
    setInsights(data.recommendations || []);
  };

  const handleQuery = async () => {
    if (!token) return;
    const res = await fetch('/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ query_text: query })
    });
    const data = await res.json();
    setResponse(data.answer || '');
  };

  const handleUpload = async () => {
    if (!token || !file) return;
    const form = new FormData();
    form.append('file', file);
    const res = await fetch(`/upload-csv?data_type=${encodeURIComponent(dataType)}` , {
      method: 'POST',
      headers: { ...authHeaders() },
      body: form
    });
    const data = await res.json();
    setUploadResult(data);
    setAnomalySummary(data.ai_summary || null);
    await fetchAnalytics();
  };

  const fetchAnalytics = async () => {
    if (!token) return;
    const res = await fetch('/analytics-summary', { headers: { ...authHeaders() } });
    const data = await res.json();
    setAnalytics(data);
  };

  useEffect(() => {
    if (token) {
      fetchInsights();
      fetchAnalytics();
    }
  }, [token]);

  // Render charts when analytics changes
  useEffect(() => {
    if (!analytics) return;
    const ctx1 = document.getElementById('chartBills');
    const ctx2 = document.getElementById('chartTop');
    if (ctx1) {
      if (chartsRef.current.chart1) chartsRef.current.chart1.destroy();
      const vals = [
        Number(analytics?.summary?.total_amount || 0),
        Number(analytics?.summary?.avg_amount || 0),
        Number(analytics?.kpis?.p95_amount || 0),
      ];
      chartsRef.current.chart1 = new Chart(ctx1, {
        type: 'bar',
        data: { labels: ['Total', 'Avg', 'P95'], datasets: [{ label: 'Amounts', data: vals, backgroundColor: ['#10b981', '#f59e0b', '#8b5cf6'] }] },
        options: { responsive: true, plugins: { legend: { display: false } } }
      });
    }
    if (ctx2) {
      if (chartsRef.current.chart2) chartsRef.current.chart2.destroy();
      const items = analytics?.top_items || [];
      chartsRef.current.chart2 = new Chart(ctx2, {
        type: 'doughnut',
        data: { labels: items.map(i=>i.name), datasets: [{ data: items.map(i=>i.amount), backgroundColor: ['#3b82f6','#22c55e','#ef4444','#f59e0b','#8b5cf6'] }] },
        options: { responsive: true }
      });
    }
  }, [analytics]);

  if (!token) {
    return (
      <div className='p-6 bg-gray-100 min-h-screen flex items-center justify-center'>
        <div className='bg-white p-6 rounded-2xl shadow w-full max-w-md'>
          <h1 className='text-2xl font-bold mb-4 text-blue-800'>Belgachia Health Point</h1>
          <p className='text-gray-600 mb-4'>Sign in to continue</p>
          <div className='space-y-3'>
            <input className='border p-2 w-full rounded' placeholder='Username' value={loginUsername} onChange={e=>setLoginUsername(e.target.value)} />
            <input type='password' className='border p-2 w-full rounded' placeholder='Password' value={loginPassword} onChange={e=>setLoginPassword(e.target.value)} />
            {loginError && <p className='text-red-600 text-sm'>{loginError}</p>}
            <button onClick={doLogin} className='bg-blue-600 text-white w-full py-2 rounded'>Sign in</button>
            <p className='text-xs text-gray-500'>Demo users: admin/admin123, manager/manager123, pharma/pharma123</p>
          </div>
        </div>
      </div>
    );
  }

  const totalAmount = analytics?.summary?.total_amount ?? 0;
  const totalRecords = analytics?.summary?.records ?? 0;
  const avgAmount = analytics?.summary?.avg_amount ?? 0;
  const kpis = analytics?.kpis || {};
  const topItems = analytics?.top_items || [];

  return (
    <div className='p-6 bg-gray-100 min-h-screen'>
      <div className='flex items-center justify-between mb-4'>
        <h1 className='text-2xl font-bold text-blue-800'>Belgachia Health Point Billing AI</h1>
        <div className='text-sm text-gray-700 flex items-center gap-3'>
          <span>{username} · {role}</span>
          <button onClick={doLogout} className='text-red-600 underline'>Logout</button>
        </div>
      </div>

      <div className='grid grid-cols-1 md:grid-cols-3 gap-4 mb-6'>
        <div className='bg-white p-4 rounded-2xl shadow'><h2 className='text-lg font-semibold text-gray-700'>Total Amount</h2><p className='text-2xl font-bold text-green-600'>₹{Number(totalAmount).toLocaleString('en-IN')}</p></div>
        <div className='bg-white p-4 rounded-2xl shadow'><h2 className='text-lg font-semibold text-gray-700'>Records</h2><p className='text-2xl font-bold text-blue-700'>{totalRecords}</p></div>
        <div className='bg-white p-4 rounded-2xl shadow'><h2 className='text-lg font-semibold text-gray-700'>Avg Amount</h2><p className='text-2xl font-bold text-yellow-600'>₹{Number(avgAmount).toLocaleString('en-IN')}</p></div>
      </div>

      <div className='grid grid-cols-1 md:grid-cols-2 gap-4 mb-6'>
        <div className='bg-white p-4 rounded-2xl shadow'>
          <h2 className='font-semibold text-gray-800 mb-2'>Bill Amounts</h2>
          <canvas id='chartBills' height='130'></canvas>
        </div>
        <div className='bg-white p-4 rounded-2xl shadow'>
          <h2 className='font-semibold text-gray-800 mb-2'>Top Items</h2>
          <canvas id='chartTop' height='130'></canvas>
        </div>
      </div>

      <div className='grid grid-cols-1 md:grid-cols-3 gap-4 mb-6'>
        <div className='bg-white p-4 rounded-2xl shadow'><h2 className='text-lg font-semibold text-gray-700'>P95 Bill</h2><p className='text-2xl font-bold text-purple-700'>₹{Number(kpis.p95_amount || 0).toLocaleString('en-IN')}</p></div>
        <div className='bg-white p-4 rounded-2xl shadow'><h2 className='text-lg font-semibold text-gray-700'>Median Bill</h2><p className='text-2xl font-bold text-indigo-700'>₹{Number(kpis.p50_amount || 0).toLocaleString('en-IN')}</p></div>
        <div className='bg-white p-4 rounded-2xl shadow'><h2 className='text-lg font-semibold text-gray-700'>Bills ≥ ₹10,000</h2><p className='text-2xl font-bold text-rose-700'>{Number(kpis.num_large_bills_10k || 0)}</p></div>
      </div>

      <div className='bg-white p-4 rounded-2xl shadow mb-6'>
        <h2 className='font-semibold text-gray-800 mb-3'>Bulk CSV Upload</h2>
        <div className='flex flex-col md:flex-row gap-3 items-start md:items-center'>
          <input type='file' accept='.csv' onChange={e=>setFile(e.target.files?.[0] || null)} className='border p-2 rounded bg-white' />
          <input className='border p-2 rounded' placeholder='data type (e.g., billing, pharmacy)' value={dataType} onChange={e=>setDataType(e.target.value)} />
          <button onClick={handleUpload} className='bg-emerald-600 text-white px-4 py-2 rounded'>Upload</button>
          <div className='flex gap-2'>
            <a className='bg-gray-700 text-white px-3 py-2 rounded' href='/export?format=csv' target='_blank' rel='noreferrer' onClick={(e)=>{ if(!token){ e.preventDefault(); } }}>Export CSV</a>
            <a className='bg-gray-700 text-white px-3 py-2 rounded' href='/export?format=xlsx' target='_blank' rel='noreferrer' onClick={(e)=>{ if(!token){ e.preventDefault(); } }}>Export XLSX</a>
          </div>
        </div>
        {uploadResult && (
          <p className='text-sm text-gray-600 mt-2'>Uploaded {uploadResult.records_uploaded} records to {uploadResult.data_type}.</p>
        )}
        {uploadResult?.anomalies && (
          <div className='mt-3'>
            <h3 className='font-semibold text-gray-700'>Detected Anomalies</h3>
            <ul className='list-disc ml-6 text-gray-700'>
              {(uploadResult.anomalies.anomalies || []).map((a, i) => <li key={i}>{a}</li>)}
            </ul>
            {(uploadResult.anomalies.suggestions || []).length > 0 && (
              <>
                <h3 className='font-semibold text-gray-700 mt-2'>Suggested Fixes</h3>
                <ul className='list-disc ml-6 text-gray-700'>
                  {uploadResult.anomalies.suggestions.map((s, i) => <li key={i}>{s}</li>)}
                </ul>
              </>
            )}
            {anomalySummary && (
              <p className='text-gray-700 mt-2 whitespace-pre-wrap'>{anomalySummary}</p>
            )}
          </div>
        )}
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
        {response && <p className='mt-3 text-gray-700 whitespace-pre-wrap'>{response}</p>}
      </div>

      {(role === 'Admin' || role === 'Manager') && (
        <div className='mt-6 grid grid-cols-1 md:grid-cols-2 gap-4'>
          <div className='bg-white p-4 rounded-2xl shadow'>
            <h2 className='font-semibold text-gray-800 mb-2'>Top Items</h2>
            <ul className='list-disc ml-6 text-gray-700'>
              {topItems.map((t, i) => <li key={i}>{t.name} – ₹{Number(t.amount).toLocaleString('en-IN')}</li>)}
            </ul>
          </div>
          <div className='bg-white p-4 rounded-2xl shadow'>
            <h2 className='font-semibold text-gray-800 mb-2'>Admin/Manager Notes</h2>
            <p className='text-gray-600'>Use API: sync Marg DB, auto-fix GST mismatches, generate reports.</p>
          </div>
        </div>
      )}
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<Dashboard />);
