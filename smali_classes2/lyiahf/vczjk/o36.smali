.class public final Llyiahf/vczjk/o36;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;


# direct methods
.method public constructor <init>(Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/o36;->this$0:Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/o36;

    iget-object v1, p0, Llyiahf/vczjk/o36;->this$0:Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/o36;-><init>(Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/o36;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xm6;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/o36;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/o36;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/o36;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/o36;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/o36;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xm6;

    iget-object v1, p0, Llyiahf/vczjk/o36;->this$0:Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    iget-object v1, v1, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;->Oooo:Llyiahf/vczjk/w26;

    const/4 v4, 0x0

    if-eqz v1, :cond_6

    iput v3, p0, Llyiahf/vczjk/o36;->label:I

    iget-object v1, v1, Llyiahf/vczjk/w26;->OooO0o0:Llyiahf/vczjk/v00;

    iget-object v3, v1, Llyiahf/vczjk/v00;->OooO0oO:Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {v3}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    iget-object v1, v1, Llyiahf/vczjk/v00;->OooO0o:Llyiahf/vczjk/r00;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v3, Llyiahf/vczjk/in6;

    invoke-direct {v3, v1, p1, v4}, Llyiahf/vczjk/in6;-><init>(Llyiahf/vczjk/kn6;Llyiahf/vczjk/xm6;Llyiahf/vczjk/yo1;)V

    iget-object p1, v1, Llyiahf/vczjk/kn6;->OooO0oO:Llyiahf/vczjk/gq8;

    invoke-virtual {p1, v3, p0}, Llyiahf/vczjk/gq8;->OooO00o(Llyiahf/vczjk/in6;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    move-object p1, v2

    :goto_1
    if-ne p1, v0, :cond_4

    goto :goto_2

    :cond_4
    move-object p1, v2

    :goto_2
    if-ne p1, v0, :cond_5

    return-object v0

    :cond_5
    return-object v2

    :cond_6
    const-string p1, "adapter"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v4
.end method
