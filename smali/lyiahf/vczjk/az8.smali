.class public final synthetic Llyiahf/vczjk/az8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qj8;

.field public final synthetic OooOOO0:Z

.field public final synthetic OooOOOO:Llyiahf/vczjk/yn4;

.field public final synthetic OooOOOo:Llyiahf/vczjk/f62;

.field public final synthetic OooOOo0:J


# direct methods
.method public synthetic constructor <init>(ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/yn4;Llyiahf/vczjk/f62;J)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/az8;->OooOOO0:Z

    iput-object p2, p0, Llyiahf/vczjk/az8;->OooOOO:Llyiahf/vczjk/qj8;

    iput-object p3, p0, Llyiahf/vczjk/az8;->OooOOOO:Llyiahf/vczjk/yn4;

    iput-object p4, p0, Llyiahf/vczjk/az8;->OooOOOo:Llyiahf/vczjk/f62;

    iput-wide p5, p0, Llyiahf/vczjk/az8;->OooOOo0:J

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/mm1;

    check-cast p1, Llyiahf/vczjk/to4;

    invoke-virtual {p1}, Llyiahf/vczjk/to4;->OooO00o()V

    iget-boolean v0, p0, Llyiahf/vczjk/az8;->OooOOO0:Z

    if-eqz v0, :cond_0

    iget-object v0, p1, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v0}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v0

    iget-object v2, p0, Llyiahf/vczjk/az8;->OooOOOO:Llyiahf/vczjk/yn4;

    iget-object v3, p0, Llyiahf/vczjk/az8;->OooOOOo:Llyiahf/vczjk/f62;

    iget-object v4, p0, Llyiahf/vczjk/az8;->OooOOO:Llyiahf/vczjk/qj8;

    invoke-interface {v4, v0, v1, v2, v3}, Llyiahf/vczjk/qj8;->OooooOo(JLlyiahf/vczjk/yn4;Llyiahf/vczjk/f62;)Llyiahf/vczjk/qqa;

    move-result-object v0

    const/16 v1, 0x38

    iget-wide v2, p0, Llyiahf/vczjk/az8;->OooOOo0:J

    invoke-static {p1, v0, v2, v3, v1}, Llyiahf/vczjk/zsa;->Oooo0(Llyiahf/vczjk/hg2;Llyiahf/vczjk/qqa;JI)V

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
