OmniAuth HubSpot
================

An OmniAuth strategy for authenticating with the HubSpot API.

## Peculiarities

HubSpot has some peculiarities in their implementation of OAuth that I've accounted for in this strategy. Be aware that the authorization process does not use OAuth2's state parameter for securing sessions. Additionally, it does not use the POST to token URL phase of OAuth; instead, the tokens we need are passed as parameters right after the initial request phase. HubSpot also authenticates with only a Client ID and a Portal ID, instead of the standard Client ID and Client Secret.

## Installing

Add the gem to your `Gemfile` and then `bundle install`.

```ruby
gem 'omniauth-hubspot'
```

## Usage

You will need to define a custom [setup phase](https://github.com/intridea/omniauth/wiki/Setup-Phase) for this strategy to work. This is because [HubSpot requires a `portalId` to be set](http://developers.hubspot.com/docs/methods/auth/oauth-overview), which is customer-specific and therefore cannot be simply passed as a parameter to provider. The above setup phase link should give you an idea of the different ways to do this. My setup phase code looks roughly like the following.

```ruby
def setup
  request.env['omniauth.strategy'].options[:portalId] = params[:hubspot][:portal_id]

  render text: "Omniauth setup phase.", status: 404
end
```

If you are using multiple providers, you'll want to wrap an if statement around that so that you only set it when you're using HubSpot.

Then, when adding the provider to your `omniauth.rb`, you will only need to specify a `client_id` and a `scope`. HubSpot's supported scopes are [here](http://developers.hubspot.com/docs/methods/auth/initiate-oauth). Note that although the documentation states to separate scopes with a `+`, you will actually need to use a space, as this is escaped into a `+`. Here is an example provider line:

```ruby
provider :hubspot, ENV['HUBSPOT_CLIENT_ID'], setup: true, scope: "contacts-rw offline"
```

Be sure to specify the `offline` scope if you want to get a refresh token that you can use to renew your access token.

## Contributing

Fork, create a branch, and create a pull request when you're done.

## License

Copyright (C) 2014 Daniel Arnold
GPL v3.
