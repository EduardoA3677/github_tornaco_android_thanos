.class public final Llyiahf/vczjk/v40;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/fg2;
.implements Llyiahf/vczjk/l86;


# instance fields
.field public OooOoOO:J

.field public OooOoo:J

.field public OooOoo0:Llyiahf/vczjk/qj8;

.field public OooOooO:Llyiahf/vczjk/yn4;

.field public OooOooo:Llyiahf/vczjk/qqa;

.field public Oooo000:Llyiahf/vczjk/qj8;

.field public Oooo00O:Llyiahf/vczjk/qqa;


# virtual methods
.method public final OooOo0o(Llyiahf/vczjk/to4;)V
    .locals 12

    iget-object v0, p0, Llyiahf/vczjk/v40;->OooOoo0:Llyiahf/vczjk/qj8;

    sget-object v1, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    if-ne v0, v1, :cond_1

    iget-wide v0, p0, Llyiahf/vczjk/v40;->OooOoOO:J

    sget-wide v2, Llyiahf/vczjk/n21;->OooOO0:J

    invoke-static {v0, v1, v2, v3}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result v0

    if-nez v0, :cond_0

    iget-wide v2, p0, Llyiahf/vczjk/v40;->OooOoOO:J

    const/4 v9, 0x0

    const/16 v11, 0x7e

    const-wide/16 v4, 0x0

    const-wide/16 v6, 0x0

    const/4 v8, 0x0

    const/4 v10, 0x0

    move-object v1, p1

    invoke-static/range {v1 .. v11}, Llyiahf/vczjk/hg2;->Oooooo0(Llyiahf/vczjk/hg2;JJJFLlyiahf/vczjk/h79;Llyiahf/vczjk/p21;I)V

    goto :goto_1

    :cond_0
    move-object v1, p1

    goto :goto_1

    :cond_1
    move-object v1, p1

    iget-object p1, v1, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v2

    iget-wide v4, p0, Llyiahf/vczjk/v40;->OooOoo:J

    invoke-static {v2, v3, v4, v5}, Llyiahf/vczjk/tq8;->OooO00o(JJ)Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/to4;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v0

    iget-object v2, p0, Llyiahf/vczjk/v40;->OooOooO:Llyiahf/vczjk/yn4;

    if-ne v0, v2, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/v40;->Oooo000:Llyiahf/vczjk/qj8;

    iget-object v2, p0, Llyiahf/vczjk/v40;->OooOoo0:Llyiahf/vczjk/qj8;

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/v40;->OooOooo:Llyiahf/vczjk/qqa;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    new-instance v0, Llyiahf/vczjk/u40;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/u40;-><init>(Llyiahf/vczjk/v40;Llyiahf/vczjk/to4;)V

    invoke-static {p0, v0}, Llyiahf/vczjk/bua;->Oooo000(Llyiahf/vczjk/jl5;Llyiahf/vczjk/le3;)V

    iget-object v0, p0, Llyiahf/vczjk/v40;->Oooo00O:Llyiahf/vczjk/qqa;

    const/4 v2, 0x0

    iput-object v2, p0, Llyiahf/vczjk/v40;->Oooo00O:Llyiahf/vczjk/qqa;

    :goto_0
    iput-object v0, p0, Llyiahf/vczjk/v40;->OooOooo:Llyiahf/vczjk/qqa;

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v2

    iput-wide v2, p0, Llyiahf/vczjk/v40;->OooOoo:J

    invoke-virtual {v1}, Llyiahf/vczjk/to4;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/v40;->OooOooO:Llyiahf/vczjk/yn4;

    iget-object p1, p0, Llyiahf/vczjk/v40;->OooOoo0:Llyiahf/vczjk/qj8;

    iput-object p1, p0, Llyiahf/vczjk/v40;->Oooo000:Llyiahf/vczjk/qj8;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-wide v2, p0, Llyiahf/vczjk/v40;->OooOoOO:J

    sget-wide v4, Llyiahf/vczjk/n21;->OooOO0:J

    invoke-static {v2, v3, v4, v5}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result p1

    if-nez p1, :cond_3

    iget-wide v2, p0, Llyiahf/vczjk/v40;->OooOoOO:J

    const/16 p1, 0x3c

    invoke-static {v1, v0, v2, v3, p1}, Llyiahf/vczjk/zsa;->Oooo0(Llyiahf/vczjk/hg2;Llyiahf/vczjk/qqa;JI)V

    :cond_3
    :goto_1
    invoke-virtual {v1}, Llyiahf/vczjk/to4;->OooO00o()V

    return-void
.end method

.method public final Oooooo()V
    .locals 2

    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    iput-wide v0, p0, Llyiahf/vczjk/v40;->OooOoo:J

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/v40;->OooOooO:Llyiahf/vczjk/yn4;

    iput-object v0, p0, Llyiahf/vczjk/v40;->OooOooo:Llyiahf/vczjk/qqa;

    iput-object v0, p0, Llyiahf/vczjk/v40;->Oooo000:Llyiahf/vczjk/qj8;

    invoke-static {p0}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    return-void
.end method
