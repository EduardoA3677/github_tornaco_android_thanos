.class public final Llyiahf/vczjk/es4;
.super Llyiahf/vczjk/so8;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o:Llyiahf/vczjk/nr4;

.field public final synthetic OooO0oO:Ljava/util/Set;

.field public final synthetic OooO0oo:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nr4;Ljava/util/Set;Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/es4;->OooO0o:Llyiahf/vczjk/nr4;

    iput-object p2, p0, Llyiahf/vczjk/es4;->OooO0oO:Ljava/util/Set;

    iput-object p3, p0, Llyiahf/vczjk/es4;->OooO0oo:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final OooOOo0(Ljava/lang/Object;)Z
    .locals 1

    check-cast p1, Llyiahf/vczjk/by0;

    const-string v0, "current"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/es4;->OooO0o:Llyiahf/vczjk/nr4;

    if-ne p1, v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/by0;->OoooO0()Llyiahf/vczjk/jg5;

    move-result-object p1

    const-string v0, "getStaticScope(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p1, Llyiahf/vczjk/gs4;

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/es4;->OooO0oo:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    iget-object v0, p0, Llyiahf/vczjk/es4;->OooO0oO:Ljava/util/Set;

    invoke-interface {v0, p1}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    const/4 p1, 0x0

    return p1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    return p1
.end method

.method public final bridge synthetic Oooo0O0()Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
