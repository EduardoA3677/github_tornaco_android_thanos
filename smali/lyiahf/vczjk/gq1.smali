.class public final Llyiahf/vczjk/gq1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $enabled:Z

.field final synthetic $focusRequester:Llyiahf/vczjk/w83;

.field final synthetic $manager:Llyiahf/vczjk/mk9;

.field final synthetic $offsetMapping:Llyiahf/vczjk/s86;

.field final synthetic $readOnly:Z

.field final synthetic $state:Llyiahf/vczjk/lx4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx4;Llyiahf/vczjk/w83;ZZLlyiahf/vczjk/mk9;Llyiahf/vczjk/s86;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gq1;->$state:Llyiahf/vczjk/lx4;

    iput-object p2, p0, Llyiahf/vczjk/gq1;->$focusRequester:Llyiahf/vczjk/w83;

    iput-boolean p3, p0, Llyiahf/vczjk/gq1;->$readOnly:Z

    iput-boolean p4, p0, Llyiahf/vczjk/gq1;->$enabled:Z

    iput-object p5, p0, Llyiahf/vczjk/gq1;->$manager:Llyiahf/vczjk/mk9;

    iput-object p6, p0, Llyiahf/vczjk/gq1;->$offsetMapping:Llyiahf/vczjk/s86;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/p86;

    iget-wide v0, p1, Llyiahf/vczjk/p86;->OooO00o:J

    iget-object p1, p0, Llyiahf/vczjk/gq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v2, p0, Llyiahf/vczjk/gq1;->$focusRequester:Llyiahf/vczjk/w83;

    iget-boolean v3, p0, Llyiahf/vczjk/gq1;->$readOnly:Z

    invoke-virtual {p1}, Llyiahf/vczjk/lx4;->OooO0O0()Z

    move-result v4

    if-nez v4, :cond_0

    invoke-static {v2}, Llyiahf/vczjk/w83;->OooO0O0(Llyiahf/vczjk/w83;)V

    goto :goto_0

    :cond_0
    if-nez v3, :cond_1

    iget-object p1, p1, Llyiahf/vczjk/lx4;->OooO0OO:Llyiahf/vczjk/dx8;

    if-eqz p1, :cond_1

    check-cast p1, Llyiahf/vczjk/q52;

    invoke-virtual {p1}, Llyiahf/vczjk/q52;->OooO0O0()V

    :cond_1
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/gq1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {p1}, Llyiahf/vczjk/lx4;->OooO0O0()Z

    move-result p1

    if-eqz p1, :cond_3

    iget-boolean p1, p0, Llyiahf/vczjk/gq1;->$enabled:Z

    if-eqz p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/gq1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {p1}, Llyiahf/vczjk/lx4;->OooO00o()Llyiahf/vczjk/vl3;

    move-result-object p1

    sget-object v2, Llyiahf/vczjk/vl3;->OooOOO:Llyiahf/vczjk/vl3;

    if-eq p1, v2, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/gq1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {p1}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object p1

    if-eqz p1, :cond_3

    iget-object v2, p0, Llyiahf/vczjk/gq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v3, p0, Llyiahf/vczjk/gq1;->$offsetMapping:Llyiahf/vczjk/s86;

    iget-object v4, v2, Llyiahf/vczjk/lx4;->OooO0Oo:Llyiahf/vczjk/xk2;

    const/4 v5, 0x1

    invoke-virtual {p1, v0, v1, v5}, Llyiahf/vczjk/nm9;->OooO0O0(JZ)I

    move-result p1

    invoke-interface {v3, p1}, Llyiahf/vczjk/s86;->OooO0o0(I)I

    move-result p1

    iget-object v0, v4, Llyiahf/vczjk/xk2;->OooO00o:Llyiahf/vczjk/gl9;

    invoke-static {p1, p1}, Llyiahf/vczjk/rd3;->OooO0O0(II)J

    move-result-wide v3

    const/4 p1, 0x5

    const/4 v1, 0x0

    invoke-static {v0, v1, v3, v4, p1}, Llyiahf/vczjk/gl9;->OooO00o(Llyiahf/vczjk/gl9;Llyiahf/vczjk/an;JI)Llyiahf/vczjk/gl9;

    move-result-object p1

    iget-object v0, v2, Llyiahf/vczjk/lx4;->OooOo0O:Llyiahf/vczjk/kx4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/kx4;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object p1, v2, Llyiahf/vczjk/lx4;->OooO00o:Llyiahf/vczjk/yh9;

    iget-object p1, p1, Llyiahf/vczjk/yh9;->OooO00o:Llyiahf/vczjk/an;

    iget-object p1, p1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p1

    if-lez p1, :cond_3

    sget-object p1, Llyiahf/vczjk/vl3;->OooOOOO:Llyiahf/vczjk/vl3;

    iget-object v0, v2, Llyiahf/vczjk/lx4;->OooOO0O:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/gq1;->$manager:Llyiahf/vczjk/mk9;

    new-instance v2, Llyiahf/vczjk/p86;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/p86;-><init>(J)V

    invoke-virtual {p1, v2}, Llyiahf/vczjk/mk9;->OooO0oO(Llyiahf/vczjk/p86;)V

    :cond_3
    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
