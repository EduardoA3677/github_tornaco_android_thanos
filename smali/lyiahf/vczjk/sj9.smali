.class public final Llyiahf/vczjk/sj9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sa8;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/sa8;

.field public final OooO0O0:Llyiahf/vczjk/w62;

.field public final OooO0OO:Llyiahf/vczjk/w62;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sa8;Llyiahf/vczjk/vj9;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/sj9;->OooO00o:Llyiahf/vczjk/sa8;

    new-instance p1, Llyiahf/vczjk/rj9;

    invoke-direct {p1, p2}, Llyiahf/vczjk/rj9;-><init>(Llyiahf/vczjk/vj9;)V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0Oo(Llyiahf/vczjk/le3;)Llyiahf/vczjk/w62;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/sj9;->OooO0O0:Llyiahf/vczjk/w62;

    new-instance p1, Llyiahf/vczjk/qj9;

    invoke-direct {p1, p2}, Llyiahf/vczjk/qj9;-><init>(Llyiahf/vczjk/vj9;)V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0Oo(Llyiahf/vczjk/le3;)Llyiahf/vczjk/w62;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/sj9;->OooO0OO:Llyiahf/vczjk/w62;

    return-void
.end method


# virtual methods
.method public final OooO00o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sj9;->OooO00o:Llyiahf/vczjk/sa8;

    invoke-interface {v0}, Llyiahf/vczjk/sa8;->OooO00o()Z

    move-result v0

    return v0
.end method

.method public final OooO0O0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sj9;->OooO0OO:Llyiahf/vczjk/w62;

    invoke-virtual {v0}, Llyiahf/vczjk/w62;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sj9;->OooO00o:Llyiahf/vczjk/sa8;

    invoke-interface {v0, p1, p2, p3}, Llyiahf/vczjk/sa8;->OooO0OO(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sj9;->OooO0O0:Llyiahf/vczjk/w62;

    invoke-virtual {v0}, Llyiahf/vczjk/w62;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

.method public final OooO0o0(F)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sj9;->OooO00o:Llyiahf/vczjk/sa8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/sa8;->OooO0o0(F)F

    move-result p1

    return p1
.end method
