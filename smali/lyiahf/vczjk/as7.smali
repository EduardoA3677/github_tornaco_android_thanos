.class public Llyiahf/vczjk/as7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/lz4;
.implements Llyiahf/vczjk/s17;
.implements Llyiahf/vczjk/ia9;
.implements Llyiahf/vczjk/qj8;
.implements Llyiahf/vczjk/em;
.implements Llyiahf/vczjk/vla;


# instance fields
.field public OooOOO0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooO00o()V
    .locals 4

    new-instance v0, Landroid/util/TypedValue;

    invoke-direct {v0}, Landroid/util/TypedValue;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    check-cast v1, Lnow/fortuitous/thanos/main/NavActivity;

    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v1

    sget v2, Landroidx/core/splashscreen/R$attr;->windowSplashScreenBackground:I

    const/4 v3, 0x1

    invoke-virtual {v1, v2, v0, v3}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    sget v2, Landroidx/core/splashscreen/R$attr;->windowSplashScreenAnimatedIcon:I

    invoke-virtual {v1, v2, v0, v3}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    move-result v2

    if-eqz v2, :cond_0

    iget v2, v0, Landroid/util/TypedValue;->resourceId:I

    invoke-virtual {v1, v2}, Landroid/content/res/Resources$Theme;->getDrawable(I)Landroid/graphics/drawable/Drawable;

    :cond_0
    sget v2, Landroidx/core/splashscreen/R$attr;->splashScreenIconSize:I

    invoke-virtual {v1, v2, v0, v3}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    invoke-virtual {p0, v1, v0}, Llyiahf/vczjk/as7;->OooO0o(Landroid/content/res/Resources$Theme;Landroid/util/TypedValue;)V

    return-void
.end method

.method public OooO0O0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ir5;

    if-nez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/g94;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/g0a;

    iget-object v0, v0, Llyiahf/vczjk/g0a;->OooO0O0:Llyiahf/vczjk/nk3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/va4;->OooOOO0:Llyiahf/vczjk/va4;

    return-object p1

    :cond_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/hc4;

    invoke-direct {v2}, Llyiahf/vczjk/hc4;-><init>()V

    invoke-virtual {v0, p1, v1, v2}, Llyiahf/vczjk/nk3;->OooOO0(Ljava/lang/Object;Ljava/lang/Class;Llyiahf/vczjk/zc4;)V

    iget-object p1, v2, Llyiahf/vczjk/hc4;->OooOoOO:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object p1, v2, Llyiahf/vczjk/hc4;->OooOoo:Llyiahf/vczjk/g94;

    return-object p1

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Expected one JSON element but was "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public OooO0Oo(Llyiahf/vczjk/ha9;)V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ja9;

    iget-object v1, v0, Llyiahf/vczjk/ja9;->OooOOOo:[I

    array-length v1, v1

    const/4 v2, 0x1

    move v3, v2

    :goto_0
    if-ge v3, v1, :cond_5

    iget-object v4, v0, Llyiahf/vczjk/ja9;->OooOOOo:[I

    aget v4, v4, v3

    if-eq v4, v2, :cond_4

    const/4 v5, 0x2

    if-eq v4, v5, :cond_3

    const/4 v5, 0x3

    if-eq v4, v5, :cond_2

    const/4 v5, 0x4

    if-eq v4, v5, :cond_1

    const/4 v5, 0x5

    if-eq v4, v5, :cond_0

    goto :goto_1

    :cond_0
    invoke-interface {p1, v3}, Llyiahf/vczjk/ha9;->OooO0o0(I)V

    goto :goto_1

    :cond_1
    iget-object v4, v0, Llyiahf/vczjk/ja9;->OooOo00:[[B

    aget-object v4, v4, v3

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {p1, v3, v4}, Llyiahf/vczjk/ha9;->OoooO0(I[B)V

    goto :goto_1

    :cond_2
    iget-object v4, v0, Llyiahf/vczjk/ja9;->OooOOoo:[Ljava/lang/String;

    aget-object v4, v4, v3

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {p1, v3, v4}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    goto :goto_1

    :cond_3
    iget-object v4, v0, Llyiahf/vczjk/ja9;->OooOOo:[D

    aget-wide v5, v4, v3

    invoke-interface {p1, v3, v5, v6}, Llyiahf/vczjk/ha9;->OooOOoo(ID)V

    goto :goto_1

    :cond_4
    iget-object v4, v0, Llyiahf/vczjk/ja9;->OooOOo0:[J

    aget-wide v5, v4, v3

    invoke-interface {p1, v3, v5, v6}, Llyiahf/vczjk/ha9;->OooO0OO(IJ)V

    :goto_1
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_5
    return-void
.end method

.method public OooO0o(Landroid/content/res/Resources$Theme;Landroid/util/TypedValue;)V
    .locals 2

    sget v0, Landroidx/core/splashscreen/R$attr;->postSplashScreenTheme:I

    const/4 v1, 0x1

    invoke-virtual {p1, v0, p2, v1}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    move-result p1

    if-eqz p1, :cond_0

    iget p1, p2, Landroid/util/TypedValue;->resourceId:I

    if-eqz p1, :cond_0

    iget-object p2, p0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    check-cast p2, Lnow/fortuitous/thanos/main/NavActivity;

    invoke-virtual {p2, p1}, Landroidx/appcompat/app/AppCompatActivity;->setTheme(I)V

    :cond_0
    return-void
.end method

.method public OooO0o0()[Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Lorg/chromium/support_lib_boundary/WebViewProviderFactoryBoundaryInterface;

    invoke-interface {v0}, Lorg/chromium/support_lib_boundary/WebViewProviderFactoryBoundaryInterface;->getSupportedFeatures()[Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public OooO0oO()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ja9;

    iget-object v0, v0, Llyiahf/vczjk/ma9;->OooOOO:Ljava/lang/String;

    return-object v0
.end method

.method public OooOO0(Ljava/io/Serializable;)Z
    .locals 1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v0

    invoke-virtual {v0, p1}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->setSmartStandByByPassIfHasVisibleWindowsEnabled(Z)V

    const/4 p1, 0x1

    return p1
.end method

.method public OooooOo(JLlyiahf/vczjk/yn4;Llyiahf/vczjk/f62;)Llyiahf/vczjk/qqa;
    .locals 0

    new-instance p1, Llyiahf/vczjk/of6;

    iget-object p2, p0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/qe;

    invoke-direct {p1, p2}, Llyiahf/vczjk/of6;-><init>(Llyiahf/vczjk/qe;)V

    return-object p1
.end method

.method public get(I)Llyiahf/vczjk/t23;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/t23;

    return-object p1
.end method

.method public getWebkitToCompatConverter()Lorg/chromium/support_lib_boundary/WebkitToCompatConverterBoundaryInterface;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Lorg/chromium/support_lib_boundary/WebViewProviderFactoryBoundaryInterface;

    invoke-interface {v0}, Lorg/chromium/support_lib_boundary/WebViewProviderFactoryBoundaryInterface;->getWebkitToCompatConverter()Ljava/lang/reflect/InvocationHandler;

    move-result-object v0

    const-class v1, Lorg/chromium/support_lib_boundary/WebkitToCompatConverterBoundaryInterface;

    invoke-static {v1, v0}, Llyiahf/vczjk/tg0;->OooOo0O(Ljava/lang/Class;Ljava/lang/reflect/InvocationHandler;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lorg/chromium/support_lib_boundary/WebkitToCompatConverterBoundaryInterface;

    return-object v0
.end method
