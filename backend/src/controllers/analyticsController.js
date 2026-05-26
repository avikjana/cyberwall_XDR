const Alert = require('../models/alert');
const Traffic = require('../models/traffic');
const Rule = require('../models/rule');

exports.getOverviewStats = async (req, res) => {
  try {
    const totalTraffic = await Traffic.countDocuments();
    const activeThreats = await Alert.countDocuments({ status: 'active' });
    const totalBlocked = await Rule.countDocuments({ status: 'active' });

    // Mock CPU and Memory metrics that would come from a system manager
    const systemStatus = {
      cpu: Math.floor(Math.random() * 25) + 5, // 5% - 30%
      ram: Math.floor(Math.random() * 15) + 40, // 40% - 55%
      disk: 38
    };

    res.status(200).json({
      success: true,
      data: {
        totalTraffic,
        activeThreats,
        totalBlocked,
        systemStatus
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.getProtocolDistribution = async (req, res) => {
  try {
    const distribution = await Traffic.aggregate([
      {
        $group: {
          _id: '$protocol',
          count: { $sum: 1 },
          bytes: { $sum: '$packetSize' }
        }
      },
      {
        $project: {
          protocol: '$_id',
          count: 1,
          bytes: 1,
          _id: 0
        }
      }
    ]);

    res.status(200).json({ success: true, data: distribution });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.getTopAttackers = async (req, res) => {
  try {
    const attackers = await Alert.aggregate([
      {
        $group: {
          _id: '$sourceIp',
          count: { $sum: 1 },
          threats: { $addToSet: '$threatType' }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 },
      {
        $project: {
          ip: '$_id',
          count: 1,
          threats: 1,
          _id: 0
        }
      }
    ]);

    res.status(200).json({ success: true, data: attackers });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.getThreatSeverityDistribution = async (req, res) => {
  try {
    const distribution = await Alert.aggregate([
      {
        $group: {
          _id: '$severity',
          count: { $sum: 1 }
        }
      },
      {
        $project: {
          severity: '$_id',
          count: 1,
          _id: 0
        }
      }
    ]);

    res.status(200).json({ success: true, data: distribution });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

exports.getTrafficTimeline = async (req, res) => {
  try {
    // Return aggregated bandwidth/packets in 1-minute chunks for the last 30 minutes
    const dateLimit = new Date(Date.now() - 30 * 60 * 1000);
    
    const timeline = await Traffic.aggregate([
      { $match: { timestamp: { $gte: dateLimit } } },
      {
        $group: {
          _id: {
            year: { $year: '$timestamp' },
            month: { $month: '$timestamp' },
            day: { $dayOfMonth: '$timestamp' },
            hour: { $hour: '$timestamp' },
            minute: { $minute: '$timestamp' }
          },
          count: { $sum: 1 },
          bytes: { $sum: '$packetSize' }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1, '_id.hour': 1, '_id.minute': 1 } }
    ]);

    const formattedTimeline = timeline.map(item => {
      const { year, month, day, hour, minute } = item._id;
      const timeStr = `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
      return {
        time: timeStr,
        packets: item.count,
        bytes: item.bytes
      };
    });

    res.status(200).json({ success: true, data: formattedTimeline });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};
