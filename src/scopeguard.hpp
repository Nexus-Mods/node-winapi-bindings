#include <functional>

class ScopeGuard {
public: 
    template<typename T> 
    ScopeGuard(T && cb) try : m_CB(std::forward<T>(cb)) {
    } catch(...) {
        cb();
        throw;
    }

    ScopeGuard(ScopeGuard && ref) : m_CB(std::move(ref.m_CB)) {
        ref.m_CB = nullptr;
    }

    ~ScopeGuard() {
        if (m_CB != nullptr) m_CB();
    }

    ScopeGuard(const ScopeGuard&) = delete;
    void operator=(const ScopeGuard&) = delete;

private:
    std::function<void()> m_CB;
};

