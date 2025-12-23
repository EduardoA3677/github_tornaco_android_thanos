.class public final Llyiahf/vczjk/ipa;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $animationScaleUri:Landroid/net/Uri;

.field final synthetic $applicationContext:Landroid/content/Context;

.field final synthetic $channel:Llyiahf/vczjk/rs0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/rs0;"
        }
    .end annotation
.end field

.field final synthetic $contentObserver:Llyiahf/vczjk/jpa;

.field final synthetic $resolver:Landroid/content/ContentResolver;

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Landroid/content/ContentResolver;Landroid/net/Uri;Llyiahf/vczjk/jpa;Llyiahf/vczjk/rs0;Landroid/content/Context;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ipa;->$resolver:Landroid/content/ContentResolver;

    iput-object p2, p0, Llyiahf/vczjk/ipa;->$animationScaleUri:Landroid/net/Uri;

    iput-object p3, p0, Llyiahf/vczjk/ipa;->$contentObserver:Llyiahf/vczjk/jpa;

    iput-object p4, p0, Llyiahf/vczjk/ipa;->$channel:Llyiahf/vczjk/rs0;

    iput-object p5, p0, Llyiahf/vczjk/ipa;->$applicationContext:Landroid/content/Context;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/ipa;

    iget-object v1, p0, Llyiahf/vczjk/ipa;->$resolver:Landroid/content/ContentResolver;

    iget-object v2, p0, Llyiahf/vczjk/ipa;->$animationScaleUri:Landroid/net/Uri;

    iget-object v3, p0, Llyiahf/vczjk/ipa;->$contentObserver:Llyiahf/vczjk/jpa;

    iget-object v4, p0, Llyiahf/vczjk/ipa;->$channel:Llyiahf/vczjk/rs0;

    iget-object v5, p0, Llyiahf/vczjk/ipa;->$applicationContext:Landroid/content/Context;

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/ipa;-><init>(Landroid/content/ContentResolver;Landroid/net/Uri;Llyiahf/vczjk/jpa;Llyiahf/vczjk/rs0;Landroid/content/Context;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/ipa;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ipa;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ipa;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ipa;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ipa;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_3

    if-eq v1, v3, :cond_2

    if-ne v1, v2, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ipa;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ej0;

    iget-object v4, p0, Llyiahf/vczjk/ipa;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/h43;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_0
    move-object p1, v4

    goto :goto_0

    :catchall_0
    move-exception p1

    goto/16 :goto_3

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/ipa;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ej0;

    iget-object v4, p0, Llyiahf/vczjk/ipa;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/h43;

    :try_start_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_1

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ipa;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/h43;

    iget-object v1, p0, Llyiahf/vczjk/ipa;->$resolver:Landroid/content/ContentResolver;

    iget-object v4, p0, Llyiahf/vczjk/ipa;->$animationScaleUri:Landroid/net/Uri;

    const/4 v5, 0x0

    iget-object v6, p0, Llyiahf/vczjk/ipa;->$contentObserver:Llyiahf/vczjk/jpa;

    invoke-virtual {v1, v4, v5, v6}, Landroid/content/ContentResolver;->registerContentObserver(Landroid/net/Uri;ZLandroid/database/ContentObserver;)V

    :try_start_2
    iget-object v1, p0, Llyiahf/vczjk/ipa;->$channel:Llyiahf/vczjk/rs0;

    invoke-interface {v1}, Llyiahf/vczjk/ui7;->iterator()Llyiahf/vczjk/ej0;

    move-result-object v1

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/ipa;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/ipa;->L$1:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/ipa;->label:I

    invoke-virtual {v1, p0}, Llyiahf/vczjk/ej0;->OooO0O0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v0, :cond_4

    goto :goto_2

    :cond_4
    move-object v7, v4

    move-object v4, p1

    move-object p1, v7

    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_5

    invoke-virtual {v1}, Llyiahf/vczjk/ej0;->OooO0OO()Ljava/lang/Object;

    iget-object p1, p0, Llyiahf/vczjk/ipa;->$applicationContext:Landroid/content/Context;

    invoke-virtual {p1}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object p1

    const-string v5, "animator_duration_scale"

    const/high16 v6, 0x3f800000    # 1.0f

    invoke-static {p1, v5, v6}, Landroid/provider/Settings$Global;->getFloat(Landroid/content/ContentResolver;Ljava/lang/String;F)F

    move-result p1

    new-instance v5, Ljava/lang/Float;

    invoke-direct {v5, p1}, Ljava/lang/Float;-><init>(F)V

    iput-object v4, p0, Llyiahf/vczjk/ipa;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/ipa;->L$1:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/ipa;->label:I

    invoke-interface {v4, v5, p0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    if-ne p1, v0, :cond_0

    :goto_2
    return-object v0

    :cond_5
    iget-object p1, p0, Llyiahf/vczjk/ipa;->$resolver:Landroid/content/ContentResolver;

    iget-object v0, p0, Llyiahf/vczjk/ipa;->$contentObserver:Llyiahf/vczjk/jpa;

    invoke-virtual {p1, v0}, Landroid/content/ContentResolver;->unregisterContentObserver(Landroid/database/ContentObserver;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :goto_3
    iget-object v0, p0, Llyiahf/vczjk/ipa;->$resolver:Landroid/content/ContentResolver;

    iget-object v1, p0, Llyiahf/vczjk/ipa;->$contentObserver:Llyiahf/vczjk/jpa;

    invoke-virtual {v0, v1}, Landroid/content/ContentResolver;->unregisterContentObserver(Landroid/database/ContentObserver;)V

    throw p1
.end method
