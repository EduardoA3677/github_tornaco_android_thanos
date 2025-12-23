.class public final Llyiahf/vczjk/ur4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/lh6;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ld9;

.field public final OooO0O0:Llyiahf/vczjk/l45;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/s64;)V
    .locals 5

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/ld9;

    sget-object v1, Llyiahf/vczjk/e86;->OooOo0o:Llyiahf/vczjk/e86;

    new-instance v2, Llyiahf/vczjk/kz3;

    const/4 v3, 0x0

    invoke-direct {v2, v3}, Llyiahf/vczjk/kz3;-><init>(Ljava/lang/Object;)V

    invoke-direct {v0, p1, v1, v2}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/s64;Llyiahf/vczjk/v4a;Llyiahf/vczjk/kp4;)V

    iput-object v0, p0, Llyiahf/vczjk/ur4;->OooO00o:Llyiahf/vczjk/ld9;

    iget-object p1, p1, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/l45;

    new-instance v1, Ljava/util/concurrent/ConcurrentHashMap;

    const/high16 v2, 0x3f800000    # 1.0f

    const/4 v3, 0x2

    const/4 v4, 0x3

    invoke-direct {v1, v4, v2, v3}, Ljava/util/concurrent/ConcurrentHashMap;-><init>(IFI)V

    new-instance v2, Llyiahf/vczjk/m5a;

    const/4 v3, 0x4

    invoke-direct {v2, v3}, Llyiahf/vczjk/m5a;-><init>(I)V

    const/4 v3, 0x0

    invoke-direct {v0, p1, v1, v2, v3}, Llyiahf/vczjk/l45;-><init>(Llyiahf/vczjk/q45;Ljava/util/concurrent/ConcurrentHashMap;Llyiahf/vczjk/oe3;I)V

    iput-object v0, p0, Llyiahf/vczjk/ur4;->OooO0O0:Llyiahf/vczjk/l45;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/hc3;)Z
    .locals 1

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/ur4;->OooO00o:Llyiahf/vczjk/ld9;

    iget-object p1, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s64;

    iget-object p1, p1, Llyiahf/vczjk/s64;->OooO0O0:Llyiahf/vczjk/bh6;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/hc3;Ljava/util/ArrayList;)V
    .locals 1

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ur4;->OooO0OO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/tr4;

    move-result-object p1

    invoke-interface {p2, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public final OooO0OO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/tr4;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ur4;->OooO00o:Llyiahf/vczjk/ld9;

    iget-object v0, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooO0O0:Llyiahf/vczjk/bh6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/mm7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/mm7;-><init>(Llyiahf/vczjk/hc3;)V

    new-instance v1, Llyiahf/vczjk/o0O000;

    const/16 v2, 0x16

    const/4 v3, 0x0

    invoke-direct {v1, v2, p0, v0, v3}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    iget-object v0, p0, Llyiahf/vczjk/ur4;->OooO0O0:Llyiahf/vczjk/l45;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/m45;

    invoke-direct {v2, p1, v1}, Llyiahf/vczjk/m45;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/le3;)V

    invoke-virtual {v0, v2}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-eqz p1, :cond_0

    check-cast p1, Llyiahf/vczjk/tr4;

    return-object p1

    :cond_0
    const/4 p1, 0x3

    invoke-static {p1}, Llyiahf/vczjk/l45;->OooO0oO(I)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooO0oo(Llyiahf/vczjk/hc3;Llyiahf/vczjk/oe3;)Ljava/util/Collection;
    .locals 0

    const-string p2, "fqName"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ur4;->OooO0OO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/tr4;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/tr4;->OooOoO:Llyiahf/vczjk/j45;

    invoke-virtual {p1}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_0
    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "LazyJavaPackageFragmentProvider of module "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/ur4;->OooO00o:Llyiahf/vczjk/ld9;

    iget-object v1, v1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    iget-object v1, v1, Llyiahf/vczjk/s64;->OooOOOO:Llyiahf/vczjk/dm5;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
