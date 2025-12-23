.class public final Llyiahf/vczjk/nc5;
.super Llyiahf/vczjk/o00O00o0;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/ze3;

.field public final synthetic OooO0O0:Llyiahf/vczjk/oe3;

.field public final synthetic OooO0OO:J

.field public final synthetic OooO0Oo:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;JLlyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/nc5;->OooO00o:Llyiahf/vczjk/ze3;

    iput-object p2, p0, Llyiahf/vczjk/nc5;->OooO0O0:Llyiahf/vczjk/oe3;

    iput-wide p3, p0, Llyiahf/vczjk/nc5;->OooO0OO:J

    iput-object p5, p0, Llyiahf/vczjk/nc5;->OooO0Oo:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/bd5;)V
    .locals 4

    sget-wide v0, Llyiahf/vczjk/n21;->OooO:J

    iget-wide v2, p0, Llyiahf/vczjk/nc5;->OooO0OO:J

    invoke-static {v2, v3, v0, v1}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    iput v0, p1, Llyiahf/vczjk/bd5;->OooO0o:I

    return-void

    :cond_0
    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->ooOO(J)I

    move-result v0

    iput v0, p1, Llyiahf/vczjk/bd5;->OooO0o:I

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/dv1;)V
    .locals 1

    const-string v0, "textView"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/nc5;->OooO0O0:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-void
.end method

.method public final OooO0Oo(Llyiahf/vczjk/dv1;Landroid/text/SpannableStringBuilder;)V
    .locals 1

    const-string v0, "textView"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/nc5;->OooO00o:Llyiahf/vczjk/ze3;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-void
.end method

.method public final OooO0o(Llyiahf/vczjk/wc5;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/nc5;->OooO0Oo:Llyiahf/vczjk/oe3;

    if-nez v0, :cond_0

    return-void

    :cond_0
    new-instance v1, Llyiahf/vczjk/oOO000o;

    const/16 v2, 0x1c

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/oOO000o;-><init>(Ljava/lang/Object;I)V

    iput-object v1, p1, Llyiahf/vczjk/wc5;->OooO0Oo:Llyiahf/vczjk/h05;

    return-void
.end method
