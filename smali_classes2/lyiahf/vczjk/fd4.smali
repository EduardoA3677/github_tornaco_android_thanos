.class public final Llyiahf/vczjk/fd4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/dy0;


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/vp3;

.field public static final OooO0o:Llyiahf/vczjk/hc3;

.field public static final synthetic OooO0o0:[Llyiahf/vczjk/th4;

.field public static final OooO0oO:Llyiahf/vczjk/qt5;

.field public static final OooO0oo:Llyiahf/vczjk/hy0;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/dm5;

.field public final OooO0O0:Llyiahf/vczjk/oe3;

.field public final OooO0OO:Llyiahf/vczjk/o45;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/fd4;

    const-string v2, "cloneable"

    const-string v3, "getCloneable()Lorg/jetbrains/kotlin/descriptors/impl/ClassDescriptorImpl;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const/4 v1, 0x1

    new-array v1, v1, [Llyiahf/vczjk/th4;

    aput-object v0, v1, v4

    sput-object v1, Llyiahf/vczjk/fd4;->OooO0o0:[Llyiahf/vczjk/th4;

    new-instance v0, Llyiahf/vczjk/vp3;

    const/16 v1, 0x12

    invoke-direct {v0, v1}, Llyiahf/vczjk/vp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/fd4;->OooO0Oo:Llyiahf/vczjk/vp3;

    sget-object v0, Llyiahf/vczjk/x09;->OooOO0o:Llyiahf/vczjk/hc3;

    sput-object v0, Llyiahf/vczjk/fd4;->OooO0o:Llyiahf/vczjk/hc3;

    sget-object v0, Llyiahf/vczjk/w09;->OooO0OO:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v1

    sput-object v1, Llyiahf/vczjk/fd4;->OooO0oO:Llyiahf/vczjk/qt5;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0oO()Llyiahf/vczjk/hc3;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/hy0;

    invoke-virtual {v0}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    sput-object v1, Llyiahf/vczjk/fd4;->OooO0oo:Llyiahf/vczjk/hy0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/dm5;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/g13;->OooOOoo:Llyiahf/vczjk/g13;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/fd4;->OooO00o:Llyiahf/vczjk/dm5;

    iput-object v0, p0, Llyiahf/vczjk/fd4;->OooO0O0:Llyiahf/vczjk/oe3;

    new-instance p2, Llyiahf/vczjk/o0O000;

    const/16 v0, 0xf

    const/4 v1, 0x0

    invoke-direct {p2, v0, p0, p1, v1}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    new-instance v0, Llyiahf/vczjk/o45;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v0, p0, Llyiahf/vczjk/fd4;->OooO0OO:Llyiahf/vczjk/o45;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)Z
    .locals 1

    const-string v0, "packageFqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "name"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/fd4;->OooO0oO:Llyiahf/vczjk/qt5;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/qt5;->equals(Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_0

    sget-object p2, Llyiahf/vczjk/fd4;->OooO0o:Llyiahf/vczjk/hc3;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/hc3;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/hy0;)Llyiahf/vczjk/by0;
    .locals 2

    const-string v0, "classId"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/fd4;->OooO0oo:Llyiahf/vczjk/hy0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/hy0;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/fd4;->OooO0OO:Llyiahf/vczjk/o45;

    sget-object v0, Llyiahf/vczjk/fd4;->OooO0o0:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    invoke-static {p1, v0}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ey0;

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/hc3;)Ljava/util/Collection;
    .locals 2

    const-string v0, "packageFqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/fd4;->OooO0o:Llyiahf/vczjk/hc3;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/hc3;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/fd4;->OooO0OO:Llyiahf/vczjk/o45;

    sget-object v0, Llyiahf/vczjk/fd4;->OooO0o0:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    invoke-static {p1, v0}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ey0;

    invoke-static {p1}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object p1
.end method
