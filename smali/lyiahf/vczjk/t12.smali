.class public final Llyiahf/vczjk/t12;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/fg2;


# instance fields
.field public final OooOoOO:Llyiahf/vczjk/n24;

.field public OooOoo:Z

.field public OooOoo0:Z

.field public OooOooO:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/n24;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t12;->OooOoOO:Llyiahf/vczjk/n24;

    return-void
.end method


# virtual methods
.method public final OooOo0o(Llyiahf/vczjk/to4;)V
    .locals 12

    invoke-virtual {p1}, Llyiahf/vczjk/to4;->OooO00o()V

    iget-boolean v0, p0, Llyiahf/vczjk/t12;->OooOoo0:Z

    iget-object v2, p1, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    if-eqz v0, :cond_0

    sget-wide v3, Llyiahf/vczjk/n21;->OooO0O0:J

    const v0, 0x3e99999a    # 0.3f

    invoke-static {v0, v3, v4}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v3

    invoke-interface {v2}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v6

    const/4 v9, 0x0

    const/4 v10, 0x0

    move-wide v2, v3

    const-wide/16 v4, 0x0

    const/4 v8, 0x0

    const/16 v11, 0x7a

    move-object v1, p1

    invoke-static/range {v1 .. v11}, Llyiahf/vczjk/hg2;->Oooooo0(Llyiahf/vczjk/hg2;JJJFLlyiahf/vczjk/h79;Llyiahf/vczjk/p21;I)V

    return-void

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/t12;->OooOoo:Z

    if-nez v0, :cond_2

    iget-boolean v0, p0, Llyiahf/vczjk/t12;->OooOooO:Z

    if-eqz v0, :cond_1

    goto :goto_0

    :cond_1
    return-void

    :cond_2
    :goto_0
    sget-wide v0, Llyiahf/vczjk/n21;->OooO0O0:J

    const v3, 0x3dcccccd    # 0.1f

    invoke-static {v3, v0, v1}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v0

    invoke-interface {v2}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v6

    const/4 v9, 0x0

    const/4 v10, 0x0

    const-wide/16 v4, 0x0

    const/4 v8, 0x0

    const/16 v11, 0x7a

    move-wide v2, v0

    move-object v1, p1

    invoke-static/range {v1 .. v11}, Llyiahf/vczjk/hg2;->Oooooo0(Llyiahf/vczjk/hg2;JJJFLlyiahf/vczjk/h79;Llyiahf/vczjk/p21;I)V

    return-void
.end method

.method public final o0O0O00()V
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/s12;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/s12;-><init>(Llyiahf/vczjk/t12;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v2, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method
