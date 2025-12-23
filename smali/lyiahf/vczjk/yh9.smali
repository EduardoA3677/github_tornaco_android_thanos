.class public final Llyiahf/vczjk/yh9;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Ljava/util/List;

.field public final OooO00o:Llyiahf/vczjk/an;

.field public final OooO0O0:Llyiahf/vczjk/rn9;

.field public final OooO0OO:I

.field public final OooO0Oo:I

.field public final OooO0o:I

.field public final OooO0o0:Z

.field public final OooO0oO:Llyiahf/vczjk/f62;

.field public final OooO0oo:Llyiahf/vczjk/aa3;

.field public OooOO0:Llyiahf/vczjk/oq5;

.field public OooOO0O:Llyiahf/vczjk/yn4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/an;Llyiahf/vczjk/rn9;ZLlyiahf/vczjk/f62;Llyiahf/vczjk/aa3;I)V
    .locals 0

    sget-object p6, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/yh9;->OooO00o:Llyiahf/vczjk/an;

    iput-object p2, p0, Llyiahf/vczjk/yh9;->OooO0O0:Llyiahf/vczjk/rn9;

    const p1, 0x7fffffff

    iput p1, p0, Llyiahf/vczjk/yh9;->OooO0OO:I

    const/4 p1, 0x1

    iput p1, p0, Llyiahf/vczjk/yh9;->OooO0Oo:I

    iput-boolean p3, p0, Llyiahf/vczjk/yh9;->OooO0o0:Z

    iput p1, p0, Llyiahf/vczjk/yh9;->OooO0o:I

    iput-object p4, p0, Llyiahf/vczjk/yh9;->OooO0oO:Llyiahf/vczjk/f62;

    iput-object p5, p0, Llyiahf/vczjk/yh9;->OooO0oo:Llyiahf/vczjk/aa3;

    iput-object p6, p0, Llyiahf/vczjk/yh9;->OooO:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/yn4;)V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/yh9;->OooOO0:Llyiahf/vczjk/oq5;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/yh9;->OooOO0O:Llyiahf/vczjk/yn4;

    if-ne p1, v1, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/oq5;->OooO00o()Z

    move-result v1

    if-eqz v1, :cond_1

    :cond_0
    iput-object p1, p0, Llyiahf/vczjk/yh9;->OooOO0O:Llyiahf/vczjk/yn4;

    iget-object v0, p0, Llyiahf/vczjk/yh9;->OooO0O0:Llyiahf/vczjk/rn9;

    invoke-static {v0, p1}, Llyiahf/vczjk/er8;->OooOOoo(Llyiahf/vczjk/rn9;Llyiahf/vczjk/yn4;)Llyiahf/vczjk/rn9;

    move-result-object v3

    new-instance v1, Llyiahf/vczjk/oq5;

    iget-object v2, p0, Llyiahf/vczjk/yh9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v4, p0, Llyiahf/vczjk/yh9;->OooO:Ljava/util/List;

    iget-object v5, p0, Llyiahf/vczjk/yh9;->OooO0oO:Llyiahf/vczjk/f62;

    iget-object v6, p0, Llyiahf/vczjk/yh9;->OooO0oo:Llyiahf/vczjk/aa3;

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/oq5;-><init>(Llyiahf/vczjk/an;Llyiahf/vczjk/rn9;Ljava/util/List;Llyiahf/vczjk/f62;Llyiahf/vczjk/aa3;)V

    move-object v0, v1

    :cond_1
    iput-object v0, p0, Llyiahf/vczjk/yh9;->OooOO0:Llyiahf/vczjk/oq5;

    return-void
.end method
