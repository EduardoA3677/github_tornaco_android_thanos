.class public final Llyiahf/vczjk/ys;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $listener:Llyiahf/vczjk/vs;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vs;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ys;->$listener:Llyiahf/vczjk/vs;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/ys;

    iget-object v0, p0, Llyiahf/vczjk/ys;->$listener:Llyiahf/vczjk/vs;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/ys;-><init>(Llyiahf/vczjk/vs;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ys;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ys;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ys;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/ys;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ys;->$listener:Llyiahf/vczjk/vs;

    check-cast p1, Llyiahf/vczjk/vz5;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/kd5;

    iget-object p1, p1, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast p1, Lnow/fortuitous/thanos/apps/AppDetailsActivity;

    invoke-direct {v0, p1}, Llyiahf/vczjk/kd5;-><init>(Landroid/content/Context;)V

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->pre_message_backup_success:I

    invoke-virtual {p1, v1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object v1

    iget-object v2, v0, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s3;

    iput-object v1, v2, Llyiahf/vczjk/s3;->OooO0o:Ljava/lang/CharSequence;

    const/4 v1, 0x1

    iput-boolean v1, v2, Llyiahf/vczjk/s3;->OooOOO0:Z

    const v1, 0x104000a

    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/kd5;->OooOo00(ILandroid/content/DialogInterface$OnClickListener;)V

    invoke-virtual {v0}, Llyiahf/vczjk/w3;->OooOOOO()Llyiahf/vczjk/x3;

    iget-object p1, p1, Lnow/fortuitous/thanos/apps/AppDetailsActivity;->OoooO00:Llyiahf/vczjk/dl5;

    invoke-virtual {p1}, Llyiahf/vczjk/dl5;->OooO00o()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
