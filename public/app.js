// Auto-detect backend: Render in production, localhost for dev
const API_URL = window.location.hostname === "localhost" || window.location.protocol === "file:"
    ? "http://localhost:8000"
    : "https://rps-compare.onrender.com";

document.addEventListener('DOMContentLoaded', () => {
    const compareBtn = document.getElementById('compare-btn');
    const bestInput = document.getElementById('best-input');
    const badInput = document.getElementById('bad-input');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    let lastResults = null;

    // Wake up the Render backend immediately on page load
    fetch(`${API_URL}/health`).catch(() => {});

    // Tab switching
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            tab.classList.add('active');
            document.getElementById(tab.dataset.tab).classList.add('active');
        });
    });

    compareBtn.addEventListener('click', async () => {
        const bestDomains = bestInput.value.split('\n').map(d => d.trim()).filter(d => d);
        const badDomains = badInput.value.split('\n').map(d => d.trim()).filter(d => d);

        if (bestDomains.length === 0 || badDomains.length === 0) {
            alert("Please enter domains in both columns.");
            return;
        }

        loading.style.display = 'flex';
        compareBtn.disabled = true;

        try {
            const response = await fetch(`${API_URL}/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ best: bestDomains, bad: badDomains })
            });

            if (!response.ok) throw new Error("Analysis failed");

            const data = await response.json();
            lastResults = data;
            renderResults(data);
            results.style.display = 'block';
            results.scrollIntoView({ behavior: 'smooth' });
        } catch (error) {
            console.error(error);
            alert(`Analysis Error: ${error.message}\n\nThis usually happens if the backend server is still waking up (Render Free Tier) or if there is a network issue. Please wait 30 seconds and try again.`);
        } finally {
            loading.style.display = 'none';
            compareBtn.disabled = false;
        }
    });

    function renderResults(data) {
        // Summary Cards
        const summaryHtml = `
            ${Components.renderStatCard("Best Avg Score", Math.round(data.summary.best.avg_score))}
            ${Components.renderStatCard("Bad Avg Score", Math.round(data.summary.bad.avg_score))}
            ${Components.renderStatCard("Best SPF Valid", Math.round(data.summary.best.spf_valid_pct), "%")}
        `;
        document.getElementById('summary-cards').innerHTML = summaryHtml;

        // Insights
        const insightsHtml = data.insights.map(i => Components.renderInsight(i)).join('');
        document.getElementById('insights-content').innerHTML = insightsHtml || "No major differences detected.";

        // Conclusion Logic
        const conclusionBox = document.getElementById('conclusion-box');
        const conclusionText = document.getElementById('conclusion-text');
        
        if (data.differences.length > 0) {
            const topDiff = data.differences.reduce((prev, current) => (Math.abs(prev.diff) > Math.abs(current.diff)) ? prev : current);
            let summary = `Analysis of ${data.best_domains.length + data.bad_domains.length} domains revealed a clear technical gap. `;
            
            if (data.summary.best.avg_score > data.summary.bad.avg_score + 15) {
                summary += `The **Best Group** significantly outperforms the Bad group with an average trust score of **${Math.round(data.summary.best.avg_score)}/100**. `;
            }

            summary += `The most critical difference is in **${topDiff.metric}**, where the Best group has a **${Math.abs(topDiff.diff).toFixed(1)}% advantage**. `;
            
            if (data.summary.best.spf_valid_pct > data.summary.bad.spf_valid_pct + 20) {
                summary += "This suggests that the Bad group likely suffers from poor email authentication setup, leading to higher spam filtering. ";
            }

            if (data.summary.best.google_verify_pct > data.summary.bad.google_verify_pct + 10) {
                summary += "Furthermore, the Best group's integration with Google services indicates a more professional and monitored email infrastructure.";
            }

            conclusionText.innerHTML = summary;
            conclusionBox.style.display = 'block';
        } else {
            conclusionBox.style.display = 'none';
        }

        // Differences Table
        const diffRows = data.differences.map(d => Components.renderDiffRow(d)).join('');
        document.querySelector('#diff-table tbody').innerHTML = diffRows || "<tr><td colspan='4' style='text-align:center'>Insufficient data for significant differences.</td></tr>";

        // Scores
        const bestScoreRows = data.best_domains.map(d => Components.renderScoreRow(d)).join('');
        const badScoreRows = data.bad_domains.map(d => Components.renderScoreRow(d)).join('');
        document.querySelector('#best-score-table tbody').innerHTML = bestScoreRows;
        document.querySelector('#bad-score-table tbody').innerHTML = badScoreRows;

        // ISP Health
        const bestIspItems = data.best_domains.map(d => Components.renderISPItem(d.domain, d)).join('');
        const badIspItems = data.bad_domains.map(d => Components.renderISPItem(d.domain, d)).join('');
        document.getElementById('best-isp-content').innerHTML = bestIspItems;
        document.getElementById('bad-isp-content').innerHTML = badIspItems;

        // Raw Data
        document.getElementById('raw-output').textContent = JSON.stringify(data, null, 2);
    }

    document.getElementById('export-json').addEventListener('click', () => {
        if (!lastResults) return;
        const blob = new Blob([JSON.stringify(lastResults, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `domain_comparison_${new Date().getTime()}.json`;
        a.click();
    });

    document.getElementById('export-csv').addEventListener('click', () => {
        if (!lastResults) return;
        
        const allDomains = [
            ...lastResults.best_domains.map(d => ({ ...d, group: 'Best' })),
            ...lastResults.bad_domains.map(d => ({ ...d, group: 'Bad' }))
        ];

        if (allDomains.length === 0) return;

        const headers = ["Group", "Domain", "Score", "SPF Valid", "DMARC Policy", "Age Days", "Registrar"];
        const rows = allDomains.map(d => [
            d.group,
            d.domain,
            d.score,
            d.email_auth.spf.valid,
            d.email_auth.dmarc.policy,
            d.metadata.age_days || "N/A",
            (d.metadata.registrar || "N/A").replace(/,/g, "")
        ]);

        const csvContent = [headers, ...rows].map(e => e.join(",")).join("\n");
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `domain_comparison_${new Date().getTime()}.csv`;
        a.click();
    });
});
