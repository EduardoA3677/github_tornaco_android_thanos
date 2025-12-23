.class public abstract synthetic Llyiahf/vczjk/gr9;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static bridge synthetic OooO(Landroid/animation/AnimatorSet;J)V
    .locals 0

    invoke-virtual {p0, p1, p2}, Landroid/animation/AnimatorSet;->setCurrentPlayTime(J)V

    return-void
.end method

.method public static synthetic OooO00o()Landroid/app/NotificationChannel;
    .locals 3

    new-instance v0, Landroid/app/NotificationChannel;

    const-string v1, "NR-Mock"

    const/4 v2, 0x4

    invoke-direct {v0, v1, v1, v2}, Landroid/app/NotificationChannel;-><init>(Ljava/lang/String;Ljava/lang/CharSequence;I)V

    return-object v0
.end method

.method public static bridge synthetic OooO0O0(JLjava/time/Duration;)Ljava/time/Duration;
    .locals 1

    sget-object v0, Ljava/time/temporal/ChronoUnit;->MILLIS:Ljava/time/temporal/ChronoUnit;

    invoke-virtual {p2, p0, p1, v0}, Ljava/time/Duration;->plus(JLjava/time/temporal/TemporalUnit;)Ljava/time/Duration;

    move-result-object p0

    return-object p0
.end method

.method public static bridge synthetic OooO0OO(Ljava/time/temporal/ChronoUnit;)Ljava/time/Duration;
    .locals 0

    invoke-virtual {p0}, Ljava/time/temporal/ChronoUnit;->getDuration()Ljava/time/Duration;

    move-result-object p0

    return-object p0
.end method

.method public static bridge synthetic OooO0Oo(Ljava/time/temporal/Temporal;Ljava/time/Instant;)Ljava/time/Duration;
    .locals 0

    invoke-static {p0, p1}, Ljava/time/Duration;->between(Ljava/time/temporal/Temporal;Ljava/time/temporal/Temporal;)Ljava/time/Duration;

    move-result-object p0

    return-object p0
.end method

.method public static bridge synthetic OooO0o(II)Ljava/time/LocalTime;
    .locals 0

    invoke-static {p0, p1}, Ljava/time/LocalTime;->of(II)Ljava/time/LocalTime;

    move-result-object p0

    return-object p0
.end method

.method public static bridge synthetic OooO0o0(Ljava/time/temporal/Temporal;Ljava/time/temporal/Temporal;)Ljava/time/Duration;
    .locals 0

    invoke-static {p0, p1}, Ljava/time/Duration;->between(Ljava/time/temporal/Temporal;Ljava/time/temporal/Temporal;)Ljava/time/Duration;

    move-result-object p0

    return-object p0
.end method

.method public static bridge synthetic OooO0oO()Ljava/time/temporal/ChronoUnit;
    .locals 1

    sget-object v0, Ljava/time/temporal/ChronoUnit;->MILLIS:Ljava/time/temporal/ChronoUnit;

    return-object v0
.end method

.method public static synthetic OooO0oo()V
    .locals 1

    new-instance v0, Landroid/app/NotificationChannel;

    return-void
.end method

.method public static bridge synthetic OooOO0(Landroid/net/ConnectivityManager;Landroid/net/NetworkRequest;Llyiahf/vczjk/j06;Landroid/os/Handler;)V
    .locals 0

    invoke-virtual {p0, p1, p2, p3}, Landroid/net/ConnectivityManager;->registerNetworkCallback(Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager$NetworkCallback;Landroid/os/Handler;)V

    return-void
.end method

.method public static bridge synthetic OooOO0O(Landroid/view/ViewParent;Landroid/view/View;Landroid/view/View;)V
    .locals 0

    invoke-interface {p0, p1, p2}, Landroid/view/ViewParent;->onDescendantInvalidated(Landroid/view/View;Landroid/view/View;)V

    return-void
.end method
