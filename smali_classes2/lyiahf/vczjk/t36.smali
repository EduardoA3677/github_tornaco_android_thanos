.class public final Llyiahf/vczjk/t36;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $progressDialog:Llyiahf/vczjk/dl5;

.field label:I

.field final synthetic this$0:Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;


# direct methods
.method public constructor <init>(Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;Llyiahf/vczjk/yo1;Llyiahf/vczjk/dl5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/t36;->this$0:Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    iput-object p3, p0, Llyiahf/vczjk/t36;->$progressDialog:Llyiahf/vczjk/dl5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/t36;

    iget-object v0, p0, Llyiahf/vczjk/t36;->this$0:Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    iget-object v1, p0, Llyiahf/vczjk/t36;->$progressDialog:Llyiahf/vczjk/dl5;

    invoke-direct {p1, v0, p2, v1}, Llyiahf/vczjk/t36;-><init>(Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;Llyiahf/vczjk/yo1;Llyiahf/vczjk/dl5;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/t36;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/t36;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/t36;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/t36;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/t36;->this$0:Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    sget v1, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;->OoooO00:I

    invoke-virtual {p1}, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;->OooOoOO()Llyiahf/vczjk/l46;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/s36;

    iget-object v3, p0, Llyiahf/vczjk/t36;->$progressDialog:Llyiahf/vczjk/dl5;

    iget-object v4, p0, Llyiahf/vczjk/t36;->this$0:Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    const/4 v5, 0x0

    invoke-direct {v1, v4, v5, v3}, Llyiahf/vczjk/s36;-><init>(Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;Llyiahf/vczjk/yo1;Llyiahf/vczjk/dl5;)V

    iput v2, p0, Llyiahf/vczjk/t36;->label:I

    iget-object p1, p1, Llyiahf/vczjk/l46;->OooO0o:Llyiahf/vczjk/ss0;

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/rs;->OooOOOO(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
