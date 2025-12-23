.class public final Llyiahf/vczjk/in7;
.super Llyiahf/vczjk/hn7;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/m66;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/m66;Llyiahf/vczjk/jn7;)V
    .locals 0

    invoke-direct {p0, p2}, Llyiahf/vczjk/hn7;-><init>(Llyiahf/vczjk/jn7;)V

    iput-object p1, p0, Llyiahf/vczjk/in7;->OooO0O0:Llyiahf/vczjk/m66;

    return-void
.end method


# virtual methods
.method public final OooO0Oo()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/in7;->OooO0O0:Llyiahf/vczjk/m66;

    invoke-interface {v0}, Llyiahf/vczjk/m66;->OooOOo0()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/qb4;Llyiahf/vczjk/gn7;)V
    .locals 1

    iget-object v0, p3, Llyiahf/vczjk/gn7;->OooO0o:Llyiahf/vczjk/r1a;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/r1a;->OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;

    move-result-object p2

    if-nez p2, :cond_1

    iget-boolean v0, p3, Llyiahf/vczjk/gn7;->OooO0oO:Z

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    return-void

    :cond_1
    :goto_0
    iget-object v0, p3, Llyiahf/vczjk/gn7;->OooO0O0:Ljava/lang/reflect/Field;

    iget-boolean p3, p3, Llyiahf/vczjk/gn7;->OooO0oo:Z

    if-nez p3, :cond_2

    invoke-virtual {v0, p1, p2}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    return-void

    :cond_2
    const/4 p1, 0x0

    invoke-static {v0, p1}, Llyiahf/vczjk/dn7;->OooO0Oo(Ljava/lang/reflect/AccessibleObject;Z)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/x94;

    const-string p3, "Cannot set value of \'static final\' "

    invoke-static {p3, p1}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw p2
.end method

.method public final OooO0o0(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    return-object p1
.end method
