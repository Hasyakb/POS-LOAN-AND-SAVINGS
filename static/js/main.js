document.addEventListener('DOMContentLoaded', () => {
    const socket = io();

    // Handle new transactions for audit_logs and reports
    socket.on('new_transaction', (data) => {
        // Update audit logs table
        const auditTable = document.getElementById('audit-table')?.getElementsByTagName('tbody')[0];
        if (auditTable) {
            const row = auditTable.insertRow(0);
            row.className = 'hover:bg-gray-50';
            row.innerHTML = `
                <td class="border border-gray-300 p-2">${data.id}</td>
                <td class="border border-gray-300 p-2">${data.type}</td>
                <td class="border border-gray-300 p-2">${data.customer_name}</td>
                <td class="border border-gray-300 p-2">${data.amount}</td>
                <td class="border border-gray-300 p-2">${data.details}</td>
                <td class="border border-gray-300 p-2">${data.created_by}</td>
                <td class="border border-gray-300 p-2">${data.created_at}</td>
            `;
        }

        // Update reports transaction table and chart
        const reportType = document.getElementById('report_type')?.value;
        if (reportType === 'transaction') {
            const transactionTable = document.getElementById('transaction-table')?.getElementsByTagName('tbody')[0];
            if (transactionTable) {
                const row = transactionTable.insertRow(0);
                row.className = 'hover:bg-gray-50';
                row.innerHTML = `
                    <td class="border border-gray-300 p-2">${data.id}</td>
                    <td class="border border-gray-300 p-2">${data.type}</td>
                    <td class="border border-gray-300 p-2">${data.amount}</td>
                    <td class="border border-gray-300 p-2">${data.details}</td>
                    <td class="border border-gray-300 p-2">${data.customer_name}</td>
                    <td class="border border-gray-300 p-2">${data.created_by}</td>
                    <td class="border border-gray-300 p-2">${data.created_at}</td>
                `;
            }
            const ctx = document.getElementById('transactionChart')?.getContext('2d');
            if (ctx && window.transactionChart) {
                window.transactionChart.data.labels.unshift(data.customer_name);
                window.transactionChart.data.datasets[0].data.unshift(parseFloat(data.amount) || 0);
                window.transactionChart.update();
            }
        }
    });

    // Validate chart data existence
    if (typeof customerChartData === 'undefined' || typeof staffChartData === 'undefined' || typeof transactionChartData === 'undefined') {
        console.error('Chart data is not defined. Ensure customerChartData, staffChartData, and transactionChartData are properly passed from the server.');
        return;
    }

    // Log raw data for debugging
    console.log('Raw customerChartData:', customerChartData);
    console.log('Raw staffChartData:', staffChartData);
    console.log('Raw transactionChartData:', transactionChartData);

    // Validate data structure
    if (!customerChartData.labels || !Array.isArray(customerChartData.labels) ||
        !customerChartData.loans || !Array.isArray(customerChartData.loans) ||
        !customerChartData.savings || !Array.isArray(customerChartData.savings)) {
        console.error('Invalid customerChartData structure. Expected {labels: Array, loans: Array, savings: Array}. Got:', customerChartData);
        return;
    }
    if (!staffChartData.labels || !Array.isArray(staffChartData.labels) ||
        !staffChartData.transactions || !Array.isArray(staffChartData.transactions) ||
        !staffChartData.amounts || !Array.isArray(staffChartData.amounts)) {
        console.error('Invalid staffChartData structure. Expected {labels: Array, transactions: Array, amounts: Array}. Got:', staffChartData);
        return;
    }
    if (!transactionChartData.labels || !Array.isArray(transactionChartData.labels) ||
        !transactionChartData.amounts || !Array.isArray(transactionChartData.amounts)) {
        console.error('Invalid transactionChartData structure. Expected {labels: Array, amounts: Array}. Got:', transactionChartData);
        return;
    }

    // Validate data types
    if (!customerChartData.labels.every(label => typeof label === 'string') ||
        !customerChartData.loans.every(num => typeof num === 'number' && !isNaN(num)) ||
        !customerChartData.savings.every(num => typeof num === 'number' && !isNaN(num))) {
        console.error('Invalid data types in customerChartData:', customerChartData);
        return;
    }
    if (!staffChartData.labels.every(label => typeof label === 'string') ||
        !staffChartData.transactions.every(num => typeof num === 'number' && !isNaN(num)) ||
        !staffChartData.amounts.every(num => typeof num === 'number' && !isNaN(num))) {
        console.error('Invalid data types in staffChartData:', staffChartData);
        return;
    }
    if (!transactionChartData.labels.every(label => typeof label === 'string') ||
        !transactionChartData.amounts.every(num => typeof num === 'number' && !isNaN(num))) {
        console.error('Invalid data types in transactionChartData:', transactionChartData);
        return;
    }

    // Customer Chart (Bar)
    const customerCtx = document.getElementById('customerChart');
    if (customerCtx) {
        try {
            new Chart(customerCtx.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: customerChartData.labels,
                    datasets: [
                        {
                            label: 'Total Loans',
                            data: customerChartData.loans,
                            backgroundColor: 'rgba(59, 130, 246, 0.6)', // Blue
                            borderColor: 'rgba(59, 130, 246, 1)',
                            borderWidth: 1
                        },
                        {
                            label: 'Total Savings',
                            data: customerChartData.savings,
                            backgroundColor: 'rgba(34, 197, 94, 0.6)', // Green
                            borderColor: 'rgba(34, 197, 94, 1)',
                            borderWidth: 1
                        }
                    ]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: { display: true, text: 'Amount' }
                        },
                        x: { title: { display: true, text: 'Customers' } }
                    },
                    plugins: {
                        legend: { position: 'top' },
                        title: { display: true, text: 'Customer Loans and Savings' }
                    }
                }
            });
        } catch (e) {
            console.error('Error initializing customer chart:', e);
        }
    } else {
        console.error('Customer chart canvas not found');
    }

    // Staff Chart (Pie)
    const staffCtx = document.getElementById('staffChart');
    if (staffCtx) {
        try {
            new Chart(staffCtx.getContext('2d'), {
                type: 'pie',
                data: {
                    labels: staffChartData.labels,
                    datasets: [{
                        label: 'Transaction Count',
                        data: staffChartData.transactions,
                        backgroundColor: [
                            'rgba(59, 130, 246, 0.6)', // Blue
                            'rgba(34, 197, 94, 0.6)', // Green
                            'rgba(234, 179, 8, 0.6)', // Yellow
                            'rgba(239, 68, 68, 0.6)', // Red
                            'rgba(168, 85, 247, 0.6)' // Purple
                        ],
                        borderColor: [
                            'rgba(59, 130, 246, 1)',
                            'rgba(34, 197, 94, 1)',
                            'rgba(234, 179, 8, 1)',
                            'rgba(239, 68, 68, 1)',
                            'rgba(168, 85, 247, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { position: 'top' },
                        title: { display: true, text: 'Staff Transaction Activity' }
                    }
                }
            });
        } catch (e) {
            console.error('Error initializing staff chart:', e);
        }
    } else {
        console.error('Staff chart canvas not found');
    }

    // Transaction Chart (Bar)
    const transactionCtx = document.getElementById('transactionChart');
    if (transactionCtx) {
        try {
            window.transactionChart = new Chart(transactionCtx.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: transactionChartData.labels,
                    datasets: [{
                        label: 'Transaction Amounts',
                        data: transactionChartData.amounts,
                        backgroundColor: 'rgba(168, 85, 247, 0.6)', // Purple
                        borderColor: 'rgba(168, 85, 247, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: { display: true, text: 'Amount' }
                        },
                        x: { title: { display: true, text: 'Customers' } }
                    },
                    plugins: {
                        legend: { position: 'top' },
                        title: { display: true, text: 'Transaction History' }
                    }
                }
            });
        } catch (e) {
            console.error('Error initializing transaction chart:', e);
        }
    } else {
        console.error('Transaction chart canvas not found');
    }
});