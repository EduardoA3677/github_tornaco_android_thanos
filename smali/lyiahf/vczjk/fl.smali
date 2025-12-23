.class public final Llyiahf/vczjk/fl;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Llyiahf/vczjk/qs5;

.field public final OooO00o:Llyiahf/vczjk/m1a;

.field public final OooO0O0:Ljava/lang/Object;

.field public final OooO0OO:J

.field public final OooO0Oo:Llyiahf/vczjk/rm4;

.field public OooO0o:Llyiahf/vczjk/dm;

.field public final OooO0o0:Llyiahf/vczjk/qs5;

.field public OooO0oO:J

.field public OooO0oo:J


# direct methods
.method public constructor <init>(Ljava/lang/Object;Llyiahf/vczjk/m1a;Llyiahf/vczjk/dm;JLjava/lang/Object;JLlyiahf/vczjk/le3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/fl;->OooO00o:Llyiahf/vczjk/m1a;

    iput-object p6, p0, Llyiahf/vczjk/fl;->OooO0O0:Ljava/lang/Object;

    iput-wide p7, p0, Llyiahf/vczjk/fl;->OooO0OO:J

    check-cast p9, Llyiahf/vczjk/rm4;

    iput-object p9, p0, Llyiahf/vczjk/fl;->OooO0Oo:Llyiahf/vczjk/rm4;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/fl;->OooO0o0:Llyiahf/vczjk/qs5;

    invoke-static {p3}, Llyiahf/vczjk/t51;->OooOo0O(Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/fl;->OooO0o:Llyiahf/vczjk/dm;

    iput-wide p4, p0, Llyiahf/vczjk/fl;->OooO0oO:J

    const-wide/high16 p1, -0x8000000000000000L

    iput-wide p1, p0, Llyiahf/vczjk/fl;->OooO0oo:J

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/fl;->OooO:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/fl;->OooO:Llyiahf/vczjk/qs5;

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/fl;->OooO0Oo:Llyiahf/vczjk/rm4;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-void
.end method

.method public final OooO0O0()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/fl;->OooO00o:Llyiahf/vczjk/m1a;

    check-cast v0, Llyiahf/vczjk/n1a;

    iget-object v0, v0, Llyiahf/vczjk/n1a;->OooO0O0:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/fl;->OooO0o:Llyiahf/vczjk/dm;

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method
