.class public final Llyiahf/vczjk/pn8;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO0O0:I


# instance fields
.field public final OooO00o:Llyiahf/vczjk/lea;


# direct methods
.method public constructor <init>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/lea;->OooOOO:Llyiahf/vczjk/lea;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/pn8;->OooO00o:Llyiahf/vczjk/lea;

    return-void
.end method

.method public static OooO00o(Landroidx/window/sidecar/SidecarDisplayFeature;Landroidx/window/sidecar/SidecarDisplayFeature;)Z
    .locals 2

    invoke-static {p0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    if-nez p0, :cond_1

    goto :goto_0

    :cond_1
    if-nez p1, :cond_2

    goto :goto_0

    :cond_2
    invoke-virtual {p0}, Landroidx/window/sidecar/SidecarDisplayFeature;->getType()I

    move-result v0

    invoke-virtual {p1}, Landroidx/window/sidecar/SidecarDisplayFeature;->getType()I

    move-result v1

    if-eq v0, v1, :cond_3

    :goto_0
    const/4 p0, 0x0

    return p0

    :cond_3
    invoke-virtual {p0}, Landroidx/window/sidecar/SidecarDisplayFeature;->getRect()Landroid/graphics/Rect;

    move-result-object p0

    invoke-virtual {p1}, Landroidx/window/sidecar/SidecarDisplayFeature;->getRect()Landroid/graphics/Rect;

    move-result-object p1

    invoke-static {p0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p0

    return p0
.end method

.method public static OooO0O0(Ljava/util/List;Ljava/util/List;)Z
    .locals 5

    if-ne p0, p1, :cond_0

    goto :goto_2

    :cond_0
    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result v0

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v1

    const/4 v2, 0x0

    if-eq v0, v1, :cond_1

    goto :goto_1

    :cond_1
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    move-result v0

    move v1, v2

    :goto_0
    if-ge v1, v0, :cond_3

    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroidx/window/sidecar/SidecarDisplayFeature;

    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Landroidx/window/sidecar/SidecarDisplayFeature;

    invoke-static {v3, v4}, Llyiahf/vczjk/pn8;->OooO00o(Landroidx/window/sidecar/SidecarDisplayFeature;Landroidx/window/sidecar/SidecarDisplayFeature;)Z

    move-result v3

    if-nez v3, :cond_2

    :goto_1
    return v2

    :cond_2
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_3
    :goto_2
    const/4 p0, 0x1

    return p0
.end method


# virtual methods
.method public final OooO0OO(Ljava/util/List;Landroidx/window/sidecar/SidecarDeviceState;)Ljava/util/ArrayList;
    .locals 2

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/window/sidecar/SidecarDisplayFeature;

    invoke-virtual {p0, v1, p2}, Llyiahf/vczjk/pn8;->OooO0o0(Landroidx/window/sidecar/SidecarDisplayFeature;Landroidx/window/sidecar/SidecarDeviceState;)Llyiahf/vczjk/nm3;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    return-object v0
.end method

.method public final OooO0Oo(Landroidx/window/sidecar/SidecarWindowLayoutInfo;Landroidx/window/sidecar/SidecarDeviceState;)Llyiahf/vczjk/voa;
    .locals 1

    if-nez p1, :cond_0

    new-instance p1, Llyiahf/vczjk/voa;

    sget-object p2, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-direct {p1, p2}, Llyiahf/vczjk/voa;-><init>(Ljava/util/List;)V

    return-object p1

    :cond_0
    new-instance v0, Landroidx/window/sidecar/SidecarDeviceState;

    invoke-direct {v0}, Landroidx/window/sidecar/SidecarDeviceState;-><init>()V

    invoke-static {p2}, Llyiahf/vczjk/kn8;->OooO0O0(Landroidx/window/sidecar/SidecarDeviceState;)I

    move-result p2

    invoke-static {v0, p2}, Llyiahf/vczjk/kn8;->OooO0Oo(Landroidx/window/sidecar/SidecarDeviceState;I)V

    invoke-static {p1}, Llyiahf/vczjk/kn8;->OooO0OO(Landroidx/window/sidecar/SidecarWindowLayoutInfo;)Ljava/util/List;

    move-result-object p1

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/pn8;->OooO0OO(Ljava/util/List;Landroidx/window/sidecar/SidecarDeviceState;)Ljava/util/ArrayList;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/voa;

    invoke-direct {p2, p1}, Llyiahf/vczjk/voa;-><init>(Ljava/util/List;)V

    return-object p2
.end method

.method public final OooO0o0(Landroidx/window/sidecar/SidecarDisplayFeature;Landroidx/window/sidecar/SidecarDeviceState;)Llyiahf/vczjk/nm3;
    .locals 4

    const-string v0, "feature"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/pp3;->OooOOO:Llyiahf/vczjk/pp3;

    iget-object v1, p0, Llyiahf/vczjk/pn8;->OooO00o:Llyiahf/vczjk/lea;

    const-string v2, "verificationMode"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/zba;

    invoke-direct {v2, p1, v1, v0}, Llyiahf/vczjk/zba;-><init>(Ljava/lang/Object;Llyiahf/vczjk/lea;Llyiahf/vczjk/pp3;)V

    sget-object v0, Llyiahf/vczjk/ln8;->OooOOO0:Llyiahf/vczjk/ln8;

    const-string v1, "Type must be either TYPE_FOLD or TYPE_HINGE"

    invoke-virtual {v2, v1, v0}, Llyiahf/vczjk/zba;->OooOo(Ljava/lang/String;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/rl6;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/mn8;->OooOOO0:Llyiahf/vczjk/mn8;

    const-string v2, "Feature bounds must not be 0"

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/rl6;->OooOo(Ljava/lang/String;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/rl6;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/nn8;->OooOOO0:Llyiahf/vczjk/nn8;

    const-string v2, "TYPE_FOLD must have 0 area"

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/rl6;->OooOo(Ljava/lang/String;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/rl6;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/on8;->OooOOO0:Llyiahf/vczjk/on8;

    const-string v2, "Feature be pinned to either left or top"

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/rl6;->OooOo(Ljava/lang/String;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/rl6;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/rl6;->OooO0oO()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroidx/window/sidecar/SidecarDisplayFeature;

    if-nez v0, :cond_0

    goto :goto_2

    :cond_0
    invoke-virtual {v0}, Landroidx/window/sidecar/SidecarDisplayFeature;->getType()I

    move-result v0

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v2, :cond_2

    if-eq v0, v1, :cond_1

    goto :goto_2

    :cond_1
    sget-object v0, Llyiahf/vczjk/mm3;->OooO0Oo:Llyiahf/vczjk/mm3;

    goto :goto_0

    :cond_2
    sget-object v0, Llyiahf/vczjk/mm3;->OooO0OO:Llyiahf/vczjk/mm3;

    :goto_0
    invoke-static {p2}, Llyiahf/vczjk/kn8;->OooO0O0(Landroidx/window/sidecar/SidecarDeviceState;)I

    move-result p2

    if-eqz p2, :cond_5

    if-eq p2, v2, :cond_5

    if-eq p2, v1, :cond_3

    sget-object v1, Llyiahf/vczjk/tqa;->OooOOOO:Llyiahf/vczjk/tqa;

    const/4 v2, 0x3

    if-eq p2, v2, :cond_4

    const/4 v2, 0x4

    if-eq p2, v2, :cond_5

    goto :goto_1

    :cond_3
    sget-object v1, Llyiahf/vczjk/tqa;->OooOOOo:Llyiahf/vczjk/tqa;

    :cond_4
    :goto_1
    new-instance p2, Llyiahf/vczjk/nm3;

    new-instance v2, Llyiahf/vczjk/ug0;

    invoke-virtual {p1}, Landroidx/window/sidecar/SidecarDisplayFeature;->getRect()Landroid/graphics/Rect;

    move-result-object p1

    const-string v3, "getRect(...)"

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v2, p1}, Llyiahf/vczjk/ug0;-><init>(Landroid/graphics/Rect;)V

    invoke-direct {p2, v2, v0, v1}, Llyiahf/vczjk/nm3;-><init>(Llyiahf/vczjk/ug0;Llyiahf/vczjk/mm3;Llyiahf/vczjk/tqa;)V

    return-object p2

    :cond_5
    :goto_2
    const/4 p1, 0x0

    return-object p1
.end method
