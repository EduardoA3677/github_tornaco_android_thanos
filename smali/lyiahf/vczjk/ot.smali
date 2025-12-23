.class public final Llyiahf/vczjk/ot;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $mainActivity:Landroidx/activity/ComponentActivity;

.field final synthetic $navController:Llyiahf/vczjk/ov5;

.field final synthetic $subState$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/p29;Llyiahf/vczjk/ov5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ot;->$mainActivity:Landroidx/activity/ComponentActivity;

    iput-object p2, p0, Llyiahf/vczjk/ot;->$subState$delegate:Llyiahf/vczjk/p29;

    iput-object p3, p0, Llyiahf/vczjk/ot;->$navController:Llyiahf/vczjk/ov5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/ot;

    iget-object v1, p0, Llyiahf/vczjk/ot;->$mainActivity:Landroidx/activity/ComponentActivity;

    iget-object v2, p0, Llyiahf/vczjk/ot;->$subState$delegate:Llyiahf/vczjk/p29;

    iget-object v3, p0, Llyiahf/vczjk/ot;->$navController:Llyiahf/vczjk/ov5;

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/ot;-><init>(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/p29;Llyiahf/vczjk/ov5;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/ot;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ot;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ot;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ot;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/ot;->label:I

    if-nez v0, :cond_4

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ot;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget-object p1, p0, Llyiahf/vczjk/ot;->$subState$delegate:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/cm4;

    iget-boolean p1, p1, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/ot;->$mainActivity:Landroidx/activity/ComponentActivity;

    invoke-virtual {p1}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    move-result-object p1

    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    move-result-object p1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Landroid/net/Uri;->toString()Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :cond_0
    move-object p1, v0

    :goto_0
    if-nez p1, :cond_1

    const-string p1, ""

    :cond_1
    :try_start_0
    invoke-static {p1}, Ltornaco/apps/thanox/Pages;->valueOf(Ljava/lang/String;)Ltornaco/apps/thanox/Pages;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    :goto_1
    instance-of v1, p1, Llyiahf/vczjk/ts7;

    if-eqz v1, :cond_2

    goto :goto_2

    :cond_2
    move-object v0, p1

    :goto_2
    check-cast v0, Ltornaco/apps/thanox/Pages;

    if-eqz v0, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/ot;->$navController:Llyiahf/vczjk/ov5;

    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v0

    invoke-static {p1, v0}, Llyiahf/vczjk/ov5;->OooO00o(Llyiahf/vczjk/ov5;Ljava/lang/String;)V

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_4
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
