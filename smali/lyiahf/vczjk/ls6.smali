.class public abstract Llyiahf/vczjk/ls6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:I

.field public static final synthetic OooO0O0:I


# direct methods
.method public static OooO(Landroid/content/Context;I)F
    .locals 1

    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p0

    int-to-float p1, p1

    invoke-virtual {p0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object p0

    const/4 v0, 0x1

    invoke-static {v0, p1, p0}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    move-result p0

    return p0
.end method

.method public static final OooO00o(ZZLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 3

    check-cast p3, Llyiahf/vczjk/zf1;

    const v0, -0x71c508d8

    invoke-virtual {p3, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p3, p0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p4

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v1

    if-eqz v1, :cond_1

    const/16 v1, 0x20

    goto :goto_1

    :cond_1
    const/16 v1, 0x10

    :goto_1
    or-int/2addr v0, v1

    and-int/lit16 v1, v0, 0x93

    const/16 v2, 0x92

    if-ne v1, v2, :cond_3

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_4

    :cond_3
    :goto_2
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v1, p4, 0x1

    if-eqz v1, :cond_5

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v1

    if-eqz v1, :cond_4

    goto :goto_3

    :cond_4
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :cond_5
    :goto_3
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OooOOo0()V

    new-instance v1, Llyiahf/vczjk/e4;

    const/16 v2, 0xd

    invoke-direct {v1, p2, v2}, Llyiahf/vczjk/e4;-><init>(Llyiahf/vczjk/a91;I)V

    const v2, 0x5fcbf5be

    invoke-static {v2, v1, p3}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v1

    and-int/lit8 v2, v0, 0xe

    or-int/lit16 v2, v2, 0x180

    and-int/lit8 v0, v0, 0x70

    or-int/2addr v0, v2

    invoke-static {p0, p1, v1, p3, v0}, Llyiahf/vczjk/nq9;->OooO00o(ZZLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    :goto_4
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p3

    if-eqz p3, :cond_6

    new-instance v0, Llyiahf/vczjk/bq9;

    invoke-direct {v0, p0, p1, p2, p4}, Llyiahf/vczjk/bq9;-><init>(ZZLlyiahf/vczjk/a91;I)V

    iput-object v0, p3, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_6
    return-void
.end method

.method public static final OooO0O0(Ljava/lang/String;)Ljava/lang/Class;
    .locals 3

    :try_start_0
    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception v0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Unable to find PreviewProvider \'"

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 p0, 0x27

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    const-string v1, "PreviewLogger"

    invoke-static {v1, p0, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    const/4 p0, 0x0

    return-object p0
.end method

.method public static final OooO0OO([JJ)I
    .locals 5

    array-length v0, p0

    add-int/lit8 v0, v0, -0x1

    const/4 v1, 0x0

    :goto_0
    if-gt v1, v0, :cond_2

    add-int v2, v1, v0

    ushr-int/lit8 v2, v2, 0x1

    aget-wide v3, p0, v2

    cmp-long v3, p1, v3

    if-lez v3, :cond_0

    add-int/lit8 v1, v2, 0x1

    goto :goto_0

    :cond_0
    if-gez v3, :cond_1

    add-int/lit8 v0, v2, -0x1

    goto :goto_0

    :cond_1
    return v2

    :cond_2
    add-int/lit8 v1, v1, 0x1

    neg-int p0, v1

    return p0
.end method

.method public static OooO0Oo(Landroid/view/View;Landroid/view/View;)Landroid/graphics/Rect;
    .locals 5

    const/4 v0, 0x2

    new-array v1, v0, [I

    invoke-virtual {p1, v1}, Landroid/view/View;->getLocationOnScreen([I)V

    const/4 v2, 0x0

    aget v3, v1, v2

    const/4 v4, 0x1

    aget v1, v1, v4

    new-array v0, v0, [I

    invoke-virtual {p0, v0}, Landroid/view/View;->getLocationOnScreen([I)V

    aget p0, v0, v2

    aget v0, v0, v4

    sub-int/2addr v3, p0

    sub-int/2addr v1, v0

    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    move-result p0

    add-int/2addr p0, v3

    invoke-virtual {p1}, Landroid/view/View;->getHeight()I

    move-result p1

    add-int/2addr p1, v1

    new-instance v0, Landroid/graphics/Rect;

    invoke-direct {v0, v3, v1, p0, p1}, Landroid/graphics/Rect;-><init>(IIII)V

    return-object v0
.end method

.method public static final OooO0o(Ljava/util/Collection;Ljava/util/Collection;)Ljava/util/Collection;
    .locals 1

    const-string v0, "collection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    return-object p0

    :cond_0
    if-nez p0, :cond_1

    return-object p1

    :cond_1
    instance-of v0, p0, Ljava/util/LinkedHashSet;

    if-eqz v0, :cond_2

    move-object v0, p0

    check-cast v0, Ljava/util/LinkedHashSet;

    invoke-virtual {v0, p1}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    return-object p0

    :cond_2
    new-instance v0, Ljava/util/LinkedHashSet;

    invoke-direct {v0, p0}, Ljava/util/LinkedHashSet;-><init>(Ljava/util/Collection;)V

    invoke-virtual {v0, p1}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    return-object v0
.end method

.method public static OooO0o0(Landroid/content/Context;Ljava/lang/String;)I
    .locals 6

    invoke-static {}, Landroid/os/Process;->myPid()I

    move-result v0

    invoke-static {}, Landroid/os/Process;->myUid()I

    move-result v1

    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p0, p1, v0, v1}, Landroid/content/Context;->checkPermission(Ljava/lang/String;II)I

    move-result v0

    const/4 v3, -0x1

    if-ne v0, v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {p1}, Landroid/app/AppOpsManager;->permissionToOp(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    const/4 v0, 0x0

    if-nez p1, :cond_1

    goto/16 :goto_5

    :cond_1
    if-nez v2, :cond_4

    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v2

    invoke-virtual {v2, v1}, Landroid/content/pm/PackageManager;->getPackagesForUid(I)[Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_3

    array-length v4, v2

    if-gtz v4, :cond_2

    goto :goto_0

    :cond_2
    aget-object v2, v2, v0

    goto :goto_1

    :cond_3
    :goto_0
    return v3

    :cond_4
    :goto_1
    invoke-static {}, Landroid/os/Process;->myUid()I

    move-result v3

    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v4

    const-class v5, Landroid/app/AppOpsManager;

    if-ne v3, v1, :cond_9

    invoke-static {v4, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_9

    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v4, 0x1d

    if-lt v3, v4, :cond_8

    invoke-virtual {p0, v5}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/app/AppOpsManager;

    invoke-static {}, Landroid/os/Binder;->getCallingUid()I

    move-result v4

    const/4 v5, 0x1

    if-nez v3, :cond_5

    move v2, v5

    goto :goto_2

    :cond_5
    invoke-virtual {v3, p1, v4, v2}, Landroid/app/AppOpsManager;->checkOpNoThrow(Ljava/lang/String;ILjava/lang/String;)I

    move-result v2

    :goto_2
    if-eqz v2, :cond_6

    goto :goto_4

    :cond_6
    invoke-static {p0}, Llyiahf/vczjk/xo;->OooO0Oo(Landroid/content/Context;)Ljava/lang/String;

    move-result-object p0

    if-nez v3, :cond_7

    goto :goto_3

    :cond_7
    invoke-virtual {v3, p1, v1, p0}, Landroid/app/AppOpsManager;->checkOpNoThrow(Ljava/lang/String;ILjava/lang/String;)I

    move-result v5

    :goto_3
    move v2, v5

    goto :goto_4

    :cond_8
    invoke-virtual {p0, v5}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Landroid/app/AppOpsManager;

    invoke-virtual {p0, p1, v2}, Landroid/app/AppOpsManager;->noteProxyOpNoThrow(Ljava/lang/String;Ljava/lang/String;)I

    move-result v2

    goto :goto_4

    :cond_9
    invoke-virtual {p0, v5}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Landroid/app/AppOpsManager;

    invoke-virtual {p0, p1, v2}, Landroid/app/AppOpsManager;->noteProxyOpNoThrow(Ljava/lang/String;Ljava/lang/String;)I

    move-result v2

    :goto_4
    if-nez v2, :cond_a

    :goto_5
    return v0

    :cond_a
    const/4 p0, -0x2

    return p0
.end method

.method public static OooO0oO(Ljava/lang/String;Ljava/util/Collection;)Llyiahf/vczjk/jg5;
    .locals 3

    const-string v0, "message"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "types"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Ljava/lang/Iterable;

    new-instance v0, Ljava/util/ArrayList;

    const/16 v1, 0xa

    invoke-static {p1, v1}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/uk4;

    invoke-virtual {v1}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    invoke-static {v0}, Llyiahf/vczjk/ls6;->OooOOO0(Ljava/util/ArrayList;)Llyiahf/vczjk/ct8;

    move-result-object p1

    iget v0, p1, Llyiahf/vczjk/ct8;->OooOOO0:I

    const/4 v1, 0x1

    if-eqz v0, :cond_2

    const/4 v2, 0x0

    if-eq v0, v1, :cond_1

    new-instance v0, Llyiahf/vczjk/bs0;

    new-array v2, v2, [Llyiahf/vczjk/jg5;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/ct8;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v2

    check-cast v2, [Llyiahf/vczjk/jg5;

    invoke-direct {v0, p0, v2}, Llyiahf/vczjk/bs0;-><init>(Ljava/lang/String;[Llyiahf/vczjk/jg5;)V

    goto :goto_1

    :cond_1
    invoke-virtual {p1, v2}, Llyiahf/vczjk/ct8;->get(I)Ljava/lang/Object;

    move-result-object p0

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/jg5;

    goto :goto_1

    :cond_2
    sget-object v0, Llyiahf/vczjk/ig5;->OooO0O0:Llyiahf/vczjk/ig5;

    :goto_1
    iget p0, p1, Llyiahf/vczjk/ct8;->OooOOO0:I

    if-gt p0, v1, :cond_3

    return-object v0

    :cond_3
    new-instance p0, Llyiahf/vczjk/pw4;

    invoke-direct {p0, v0}, Llyiahf/vczjk/pw4;-><init>(Llyiahf/vczjk/jg5;)V

    return-object p0
.end method

.method public static OooO0oo(Landroid/view/View;Llyiahf/vczjk/bja;)V
    .locals 5

    new-instance v0, Llyiahf/vczjk/cja;

    invoke-virtual {p0}, Landroid/view/View;->getPaddingStart()I

    move-result v1

    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    move-result v2

    invoke-virtual {p0}, Landroid/view/View;->getPaddingEnd()I

    move-result v3

    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    move-result v4

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput v1, v0, Llyiahf/vczjk/cja;->OooO00o:I

    iput v2, v0, Llyiahf/vczjk/cja;->OooO0O0:I

    iput v3, v0, Llyiahf/vczjk/cja;->OooO0OO:I

    iput v4, v0, Llyiahf/vczjk/cja;->OooO0Oo:I

    new-instance v1, Llyiahf/vczjk/xo8;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/xo8;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/xfa;->OooO00o:Ljava/util/WeakHashMap;

    invoke-static {p0, v1}, Llyiahf/vczjk/ofa;->OooOOO0(Landroid/view/View;Llyiahf/vczjk/u96;)V

    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-virtual {p0}, Landroid/view/View;->requestApplyInsets()V

    return-void

    :cond_0
    new-instance p1, Llyiahf/vczjk/zia;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    invoke-virtual {p0, p1}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    return-void
.end method

.method public static OooOO0(Landroid/view/View;)Landroid/view/ViewGroup;
    .locals 3

    const/4 v0, 0x0

    if-nez p0, :cond_0

    return-object v0

    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getRootView()Landroid/view/View;

    move-result-object v1

    const v2, 0x1020002

    invoke-virtual {v1, v2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v2

    check-cast v2, Landroid/view/ViewGroup;

    if-eqz v2, :cond_1

    return-object v2

    :cond_1
    if-eq v1, p0, :cond_2

    instance-of p0, v1, Landroid/view/ViewGroup;

    if-eqz p0, :cond_2

    check-cast v1, Landroid/view/ViewGroup;

    return-object v1

    :cond_2
    return-object v0
.end method

.method public static final OooOO0O(ILjava/lang/Class;)[Ljava/lang/Object;
    .locals 7

    const/4 p0, 0x0

    if-eqz p1, :cond_5

    :try_start_0
    invoke-virtual {p1}, Ljava/lang/Class;->getConstructors()[Ljava/lang/reflect/Constructor;

    move-result-object p1

    array-length v0, p1

    const/4 v1, 0x0

    move v2, p0

    move-object v3, v1

    :goto_0
    const/4 v4, 0x1

    if-ge p0, v0, :cond_2

    aget-object v5, p1, p0

    invoke-virtual {v5}, Ljava/lang/reflect/Constructor;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v6

    array-length v6, v6

    if-nez v6, :cond_1

    if-eqz v2, :cond_0

    :goto_1
    move-object v3, v1

    goto :goto_2

    :cond_0
    move v2, v4

    move-object v3, v5

    :cond_1
    add-int/lit8 p0, p0, 0x1

    goto :goto_0

    :cond_2
    if-nez v2, :cond_3

    goto :goto_1

    :cond_3
    :goto_2
    if-eqz v3, :cond_4

    invoke-virtual {v3, v4}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    invoke-virtual {v3, v1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    const-string p1, "null cannot be cast to non-null type androidx.compose.ui.tooling.preview.PreviewParameterProvider<*>"

    invoke-static {p0, p1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p0, Ljava/lang/ClassCastException;

    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    throw p0

    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "PreviewParameterProvider constructor can not have parameters"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
    :try_end_0
    .catch Llyiahf/vczjk/rk4; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Deploying Compose Previews with PreviewParameterProvider arguments requires adding a dependency to the kotlin-reflect library.\nConsider adding \'debugImplementation \"org.jetbrains.kotlin:kotlin-reflect:$kotlin_version\"\' to the module\'s build.gradle."

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_5
    new-array p0, p0, [Ljava/lang/Object;

    return-object p0
.end method

.method public static OooOO0o(Landroid/view/View;)Z
    .locals 1

    invoke-virtual {p0}, Landroid/view/View;->getLayoutDirection()I

    move-result p0

    const/4 v0, 0x1

    if-ne p0, v0, :cond_0

    return v0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOOO(Llyiahf/vczjk/qb4;)Llyiahf/vczjk/g94;
    .locals 2

    :try_start_0
    invoke-virtual {p0}, Llyiahf/vczjk/qb4;->o0000()I
    :try_end_0
    .catch Ljava/io/EOFException; {:try_start_0 .. :try_end_0} :catch_4
    .catch Llyiahf/vczjk/va5; {:try_start_0 .. :try_end_0} :catch_3
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_1

    const/4 v0, 0x0

    :try_start_1
    sget-object v1, Llyiahf/vczjk/x2a;->OooOoO:Llyiahf/vczjk/h94;

    invoke-virtual {v1, p0}, Llyiahf/vczjk/h94;->OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/g94;
    :try_end_1
    .catch Ljava/io/EOFException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Llyiahf/vczjk/va5; {:try_start_1 .. :try_end_1} :catch_3
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_1

    return-object p0

    :catch_0
    move-exception p0

    goto :goto_0

    :catch_1
    move-exception p0

    new-instance v0, Llyiahf/vczjk/fc4;

    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v0

    :catch_2
    move-exception p0

    new-instance v0, Llyiahf/vczjk/x94;

    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v0

    :catch_3
    move-exception p0

    new-instance v0, Llyiahf/vczjk/fc4;

    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v0

    :catch_4
    move-exception p0

    const/4 v0, 0x1

    :goto_0
    if-eqz v0, :cond_0

    sget-object p0, Llyiahf/vczjk/va4;->OooOOO0:Llyiahf/vczjk/va4;

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/fc4;

    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v0
.end method

.method public static final OooOOO0(Ljava/util/ArrayList;)Llyiahf/vczjk/ct8;
    .locals 4

    new-instance v0, Llyiahf/vczjk/ct8;

    invoke-direct {v0}, Llyiahf/vczjk/ct8;-><init>()V

    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/jg5;

    if-eqz v2, :cond_0

    sget-object v3, Llyiahf/vczjk/ig5;->OooO0O0:Llyiahf/vczjk/ig5;

    if-eq v2, v3, :cond_0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ct8;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    return-object v0
.end method

.method public static OooOOOO(ILandroid/graphics/PorterDuff$Mode;)Landroid/graphics/PorterDuff$Mode;
    .locals 1

    const/4 v0, 0x3

    if-eq p0, v0, :cond_2

    const/4 v0, 0x5

    if-eq p0, v0, :cond_1

    const/16 v0, 0x9

    if-eq p0, v0, :cond_0

    packed-switch p0, :pswitch_data_0

    return-object p1

    :pswitch_0
    sget-object p0, Landroid/graphics/PorterDuff$Mode;->ADD:Landroid/graphics/PorterDuff$Mode;

    return-object p0

    :pswitch_1
    sget-object p0, Landroid/graphics/PorterDuff$Mode;->SCREEN:Landroid/graphics/PorterDuff$Mode;

    return-object p0

    :pswitch_2
    sget-object p0, Landroid/graphics/PorterDuff$Mode;->MULTIPLY:Landroid/graphics/PorterDuff$Mode;

    return-object p0

    :cond_0
    sget-object p0, Landroid/graphics/PorterDuff$Mode;->SRC_ATOP:Landroid/graphics/PorterDuff$Mode;

    return-object p0

    :cond_1
    sget-object p0, Landroid/graphics/PorterDuff$Mode;->SRC_IN:Landroid/graphics/PorterDuff$Mode;

    return-object p0

    :cond_2
    sget-object p0, Landroid/graphics/PorterDuff$Mode;->SRC_OVER:Landroid/graphics/PorterDuff$Mode;

    return-object p0

    :pswitch_data_0
    .packed-switch 0xe
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final OooOOOo(Llyiahf/vczjk/sp3;Llyiahf/vczjk/x65;Llyiahf/vczjk/hh6;Llyiahf/vczjk/qt5;)V
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "from"

    invoke-static {p1, p0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "scopeOwner"

    invoke-static {p2, p0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "name"

    invoke-static {p3, p0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p2, Llyiahf/vczjk/ih6;

    iget-object p0, p2, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    iget-object p0, p0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object p0, p0, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    invoke-virtual {p3}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object p1

    const-string p2, "asString(...)"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "packageFqName"

    invoke-static {p0, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method

.method public static final OooOOo(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/bf7;
    .locals 8

    sget v0, Llyiahf/vczjk/re7;->OooO00o:F

    sget v1, Llyiahf/vczjk/re7;->OooO0O0:F

    const/4 v2, 0x0

    int-to-float v3, v2

    invoke-static {v0, v3}, Ljava/lang/Float;->compare(FF)I

    move-result v3

    if-lez v3, :cond_8

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v4, :cond_0

    invoke-static {p2}, Llyiahf/vczjk/c6a;->Oooo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/xr1;

    move-result-object v3

    invoke-virtual {p2, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_0
    check-cast v3, Llyiahf/vczjk/xr1;

    invoke-static {p1, p2}, Landroidx/compose/runtime/OooO0o;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object p1

    new-instance v5, Llyiahf/vczjk/el7;

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    new-instance v6, Llyiahf/vczjk/el7;

    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    sget-object v7, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {p2, v7}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/f62;

    invoke-interface {v7, v0}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v0

    iput v0, v5, Llyiahf/vczjk/el7;->element:F

    invoke-interface {v7, v1}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v0

    iput v0, v6, Llyiahf/vczjk/el7;->element:F

    invoke-virtual {p2, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_1

    if-ne v1, v4, :cond_2

    :cond_1
    new-instance v1, Llyiahf/vczjk/bf7;

    iget v0, v6, Llyiahf/vczjk/el7;->element:F

    iget v7, v5, Llyiahf/vczjk/el7;->element:F

    invoke-direct {v1, v3, p1, v0, v7}, Llyiahf/vczjk/bf7;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/qs5;FF)V

    invoke-virtual {p2, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    check-cast v1, Llyiahf/vczjk/bf7;

    invoke-virtual {p2, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p1

    and-int/lit8 v0, p3, 0xe

    xor-int/lit8 v0, v0, 0x6

    const/4 v3, 0x4

    if-le v0, v3, :cond_3

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v0

    if-nez v0, :cond_4

    :cond_3
    and-int/lit8 p3, p3, 0x6

    if-ne p3, v3, :cond_5

    :cond_4
    const/4 v2, 0x1

    :cond_5
    or-int/2addr p1, v2

    iget p3, v5, Llyiahf/vczjk/el7;->element:F

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result p3

    or-int/2addr p1, p3

    iget p3, v6, Llyiahf/vczjk/el7;->element:F

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result p3

    or-int/2addr p1, p3

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p3

    if-nez p1, :cond_6

    if-ne p3, v4, :cond_7

    :cond_6
    new-instance p3, Llyiahf/vczjk/cf7;

    invoke-direct {p3, v1, p0, v5, v6}, Llyiahf/vczjk/cf7;-><init>(Llyiahf/vczjk/bf7;ZLlyiahf/vczjk/el7;Llyiahf/vczjk/el7;)V

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast p3, Llyiahf/vczjk/le3;

    invoke-static {p3, p2}, Llyiahf/vczjk/c6a;->OooOo00(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;)V

    return-object v1

    :cond_8
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "The refresh trigger must be greater than zero!"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOOo0(Landroid/graphics/drawable/Drawable;Ljava/util/List;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/un6;
    .locals 2

    const-string p3, "imagePlugins"

    invoke-static {p1, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p2, Llyiahf/vczjk/zf1;

    const p3, 0x18649388

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const p3, 0x45ab67ec

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p3

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    or-int/2addr p3, v0

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p3, :cond_0

    sget-object p3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p3, :cond_3

    :cond_0
    instance-of p3, p0, Landroid/graphics/drawable/BitmapDrawable;

    if-eqz p3, :cond_1

    new-instance p3, Llyiahf/vczjk/cd0;

    move-object v0, p0

    check-cast v0, Landroid/graphics/drawable/BitmapDrawable;

    invoke-virtual {v0}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    move-result-object v0

    const-string v1, "getBitmap(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/kd;

    invoke-direct {v1, v0}, Llyiahf/vczjk/kd;-><init>(Landroid/graphics/Bitmap;)V

    invoke-direct {p3, v1}, Llyiahf/vczjk/cd0;-><init>(Llyiahf/vczjk/lu3;)V

    :goto_0
    move-object v0, p3

    goto :goto_1

    :cond_1
    instance-of p3, p0, Landroid/graphics/drawable/ColorDrawable;

    if-eqz p3, :cond_2

    new-instance p3, Llyiahf/vczjk/t21;

    move-object v0, p0

    check-cast v0, Landroid/graphics/drawable/ColorDrawable;

    invoke-virtual {v0}, Landroid/graphics/drawable/ColorDrawable;->getColor()I

    move-result v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooO0OO(I)J

    move-result-wide v0

    invoke-direct {p3, v0, v1}, Llyiahf/vczjk/t21;-><init>(J)V

    goto :goto_0

    :cond_2
    new-instance p3, Llyiahf/vczjk/og2;

    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->mutate()Landroid/graphics/drawable/Drawable;

    move-result-object v0

    const-string v1, "mutate(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p3, v0}, Llyiahf/vczjk/og2;-><init>(Landroid/graphics/drawable/Drawable;)V

    goto :goto_0

    :goto_1
    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v0, Llyiahf/vczjk/un6;

    const/4 p3, 0x0

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {p0}, Llyiahf/vczjk/vc6;->OoooO00(Landroid/graphics/drawable/Drawable;)Landroid/graphics/Bitmap;

    const-string p0, "<this>"

    invoke-static {v0, p0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const p0, 0x439a0674

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    new-instance p0, Ljava/util/ArrayList;

    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    goto :goto_2

    :cond_4
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result p1

    if-nez p1, :cond_5

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v0

    :cond_5
    invoke-static {p0}, Llyiahf/vczjk/q99;->OooO0o0(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    move-result-object p0

    throw p0
.end method

.method public static final OooOOoo(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 7

    invoke-interface {p0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/zsa;->Oooo0oo(Llyiahf/vczjk/or1;)V

    invoke-static {p0}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p0

    instance-of v1, p0, Llyiahf/vczjk/fc2;

    if-eqz v1, :cond_0

    check-cast p0, Llyiahf/vczjk/fc2;

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    :goto_0
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-nez p0, :cond_1

    :goto_1
    move-object p0, v1

    goto/16 :goto_6

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/fc2;->OooOOOo:Llyiahf/vczjk/qr1;

    invoke-static {v2, v0}, Llyiahf/vczjk/dn8;->o0ooOOo(Llyiahf/vczjk/qr1;Llyiahf/vczjk/or1;)Z

    move-result v3

    const/4 v4, 0x1

    if-eqz v3, :cond_2

    iput-object v1, p0, Llyiahf/vczjk/fc2;->OooOOo:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/hc2;->OooOOOO:I

    invoke-virtual {v2, v0, p0}, Llyiahf/vczjk/qr1;->o0000Ooo(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    goto :goto_5

    :cond_2
    new-instance v3, Llyiahf/vczjk/sta;

    sget-object v5, Llyiahf/vczjk/sta;->OooOOOO:Llyiahf/vczjk/up3;

    invoke-direct {v3, v5}, Llyiahf/vczjk/o000O0o;-><init>(Llyiahf/vczjk/nr1;)V

    invoke-interface {v0, v3}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v0

    iput-object v1, p0, Llyiahf/vczjk/fc2;->OooOOo:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/hc2;->OooOOOO:I

    invoke-virtual {v2, v0, p0}, Llyiahf/vczjk/qr1;->o0000Ooo(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    iget-boolean v0, v3, Llyiahf/vczjk/sta;->OooOOO:Z

    if-eqz v0, :cond_8

    invoke-static {}, Llyiahf/vczjk/vq9;->OooO00o()Llyiahf/vczjk/pr2;

    move-result-object v0

    iget-object v2, v0, Llyiahf/vczjk/pr2;->OooOOo0:Llyiahf/vczjk/xx;

    if-eqz v2, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/xx;->isEmpty()Z

    move-result v2

    goto :goto_2

    :cond_3
    move v2, v4

    :goto_2
    if-eqz v2, :cond_4

    goto :goto_1

    :cond_4
    iget-wide v2, v0, Llyiahf/vczjk/pr2;->OooOOOO:J

    const-wide v5, 0x100000000L

    cmp-long v2, v2, v5

    if-ltz v2, :cond_5

    move v2, v4

    goto :goto_3

    :cond_5
    const/4 v2, 0x0

    :goto_3
    if-eqz v2, :cond_6

    iput-object v1, p0, Llyiahf/vczjk/fc2;->OooOOo:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/hc2;->OooOOOO:I

    invoke-virtual {v0, p0}, Llyiahf/vczjk/pr2;->o0000O00(Llyiahf/vczjk/hc2;)V

    sget-object p0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    goto :goto_6

    :cond_6
    invoke-virtual {v0, v4}, Llyiahf/vczjk/pr2;->o0000oO(Z)V

    :try_start_0
    invoke-virtual {p0}, Llyiahf/vczjk/hc2;->run()V

    :cond_7
    invoke-virtual {v0}, Llyiahf/vczjk/pr2;->o0000O0O()Z

    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez v2, :cond_7

    :goto_4
    invoke-virtual {v0, v4}, Llyiahf/vczjk/pr2;->o0000(Z)V

    goto :goto_1

    :catchall_0
    move-exception v2

    :try_start_1
    invoke-virtual {p0, v2}, Llyiahf/vczjk/hc2;->OooO0o(Ljava/lang/Throwable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_4

    :catchall_1
    move-exception p0

    invoke-virtual {v0, v4}, Llyiahf/vczjk/pr2;->o0000(Z)V

    throw p0

    :cond_8
    :goto_5
    sget-object p0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    :goto_6
    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p0, v0, :cond_9

    return-object p0

    :cond_9
    return-object v1
.end method
