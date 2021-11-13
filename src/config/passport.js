const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const SlackStrategy = require('passport-slack').Strategy;
const config = require('./config');
const { tokenTypes } = require('./tokens');
const { User } = require('../models');

const jwtOptions = {
  secretOrKey: config.jwt.secret,
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
};

const jwtVerify = async (payload, done) => {
  try {
    if (payload.type !== tokenTypes.ACCESS) {
      throw new Error('Invalid token type');
    }
    const user = await User.findById(payload.sub);
    if (!user) {
      return done(null, false);
    }
    done(null, user);
  } catch (error) {
    done(error, false);
  }
};

const slackOptions = {
  clientID: config.slack.clientId,
  clientSecret: config.slack.secret,
};

const jwtStrategy = new JwtStrategy(jwtOptions, jwtVerify);
const slackStrategy = new SlackStrategy(slackOptions);

module.exports = {
  jwtStrategy,
  slackStrategy,
};
