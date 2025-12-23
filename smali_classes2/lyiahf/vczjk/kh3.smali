.class public abstract Llyiahf/vczjk/kh3;
.super Llyiahf/vczjk/kg5;
.source "SourceFile"


# static fields
.field public static final synthetic OooO0Oo:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/oo0o0Oo;

.field public final OooO0OO:Llyiahf/vczjk/o45;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/kh3;

    const-string v2, "allDescriptors"

    const-string v3, "getAllDescriptors()Ljava/util/List;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const/4 v1, 0x1

    new-array v1, v1, [Llyiahf/vczjk/th4;

    aput-object v0, v1, v4

    sput-object v1, Llyiahf/vczjk/kh3;->OooO0Oo:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/oo0o0Oo;)V
    .locals 1

    const-string v0, "storageManager"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/kh3;->OooO0O0:Llyiahf/vczjk/oo0o0Oo;

    new-instance p2, Llyiahf/vczjk/o0oOOo;

    const/16 v0, 0xe

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    new-instance v0, Llyiahf/vczjk/o45;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v0, p0, Llyiahf/vczjk/kh3;->OooO0OO:Llyiahf/vczjk/o45;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;
    .locals 3

    const-string p2, "name"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p2, p0, Llyiahf/vczjk/kh3;->OooO0OO:Llyiahf/vczjk/o45;

    sget-object v0, Llyiahf/vczjk/kh3;->OooO0Oo:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    invoke-static {p2, v0}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/util/List;

    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1

    :cond_0
    new-instance v0, Llyiahf/vczjk/ct8;

    invoke-direct {v0}, Llyiahf/vczjk/ct8;-><init>()V

    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :cond_1
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    instance-of v2, v1, Llyiahf/vczjk/ho8;

    if-eqz v2, :cond_1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/ho8;

    invoke-virtual {v2}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-static {v2, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ct8;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;
    .locals 1

    const-string p2, "kindFilter"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p2, Llyiahf/vczjk/e72;->OooOOO:Llyiahf/vczjk/e72;

    iget p2, p2, Llyiahf/vczjk/e72;->OooO0O0:I

    invoke-virtual {p1, p2}, Llyiahf/vczjk/e72;->OooO00o(I)Z

    move-result p1

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/kh3;->OooO0OO:Llyiahf/vczjk/o45;

    sget-object p2, Llyiahf/vczjk/kh3;->OooO0Oo:[Llyiahf/vczjk/th4;

    const/4 v0, 0x0

    aget-object p2, p2, v0

    invoke-static {p1, p2}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;
    .locals 3

    const-string p2, "name"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p2, p0, Llyiahf/vczjk/kh3;->OooO0OO:Llyiahf/vczjk/o45;

    sget-object v0, Llyiahf/vczjk/kh3;->OooO0Oo:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    invoke-static {p2, v0}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/util/List;

    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1

    :cond_0
    new-instance v0, Llyiahf/vczjk/ct8;

    invoke-direct {v0}, Llyiahf/vczjk/ct8;-><init>()V

    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :cond_1
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    instance-of v2, v1, Llyiahf/vczjk/sa7;

    if-eqz v2, :cond_1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/sa7;

    invoke-interface {v2}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-static {v2, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ct8;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    return-object v0
.end method

.method public abstract OooO0oo()Ljava/util/List;
.end method
