import React from 'react';

const IframeEmbed = () => {
    return (
        <div style={{ width: '100%', height: '100vh', overflow: 'hidden' }}>
            <iframe
                src="https://preview--cipher-dash-monitor.lovable.app/crypto-admin/transactions"
                title="Admin Dashboard"
                style={{ width: '100%', height: '100%', border: 'none' }}
            />
        </div>
    );
};

export default IframeEmbed;