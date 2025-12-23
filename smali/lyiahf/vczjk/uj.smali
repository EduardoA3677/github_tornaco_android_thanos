.class public final Llyiahf/vczjk/uj;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sy9;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/bz9;

.field public OooO0O0:Llyiahf/vczjk/o4;

.field public OooO0OO:Llyiahf/vczjk/yn4;

.field public final OooO0Oo:Llyiahf/vczjk/qs5;

.field public OooO0o:Llyiahf/vczjk/ny9;

.field public final OooO0o0:Llyiahf/vczjk/js5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;Llyiahf/vczjk/o4;Llyiahf/vczjk/yn4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/uj;->OooO00o:Llyiahf/vczjk/bz9;

    iput-object p2, p0, Llyiahf/vczjk/uj;->OooO0O0:Llyiahf/vczjk/o4;

    iput-object p3, p0, Llyiahf/vczjk/uj;->OooO0OO:Llyiahf/vczjk/yn4;

    new-instance p1, Llyiahf/vczjk/b24;

    const-wide/16 p2, 0x0

    invoke-direct {p1, p2, p3}, Llyiahf/vczjk/b24;-><init>(J)V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/uj;->OooO0Oo:Llyiahf/vczjk/qs5;

    sget-object p1, Llyiahf/vczjk/y78;->OooO00o:[J

    new-instance p1, Llyiahf/vczjk/js5;

    invoke-direct {p1}, Llyiahf/vczjk/js5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/uj;->OooO0o0:Llyiahf/vczjk/js5;

    return-void
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/uj;JJ)J
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/uj;->OooO0O0:Llyiahf/vczjk/o4;

    sget-object v5, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    move-wide v1, p1

    move-wide v3, p3

    invoke-interface/range {v0 .. v5}, Llyiahf/vczjk/o4;->OooO00o(JJLlyiahf/vczjk/yn4;)J

    move-result-wide p0

    return-wide p0
.end method

.method public static final OooO0o0(Llyiahf/vczjk/uj;)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/uj;->OooO0o:Llyiahf/vczjk/ny9;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/ny9;->getValue()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/b24;

    iget-wide v0, p0, Llyiahf/vczjk/b24;->OooO00o:J

    return-wide v0

    :cond_0
    iget-object p0, p0, Llyiahf/vczjk/uj;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast p0, Llyiahf/vczjk/fw8;

    invoke-virtual {p0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/b24;

    iget-wide v0, p0, Llyiahf/vczjk/b24;->OooO00o:J

    return-wide v0
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/uj;->OooO00o:Llyiahf/vczjk/bz9;

    invoke-virtual {v0}, Llyiahf/vczjk/bz9;->OooO0o()Llyiahf/vczjk/sy9;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/sy9;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0OO()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/uj;->OooO00o:Llyiahf/vczjk/bz9;

    invoke-virtual {v0}, Llyiahf/vczjk/bz9;->OooO0o()Llyiahf/vczjk/sy9;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/sy9;->OooO0OO()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method
