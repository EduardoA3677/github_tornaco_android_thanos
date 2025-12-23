.class public final Llyiahf/vczjk/ku4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/rm4;

.field public final OooO0O0:Llyiahf/vczjk/ld9;

.field public OooO0OO:Llyiahf/vczjk/ed5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    check-cast p1, Llyiahf/vczjk/rm4;

    iput-object p1, p0, Llyiahf/vczjk/ku4;->OooO00o:Llyiahf/vczjk/rm4;

    new-instance p1, Llyiahf/vczjk/ld9;

    const/16 v0, 0x1d

    invoke-direct {p1, v0}, Llyiahf/vczjk/ld9;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/ku4;->OooO0O0:Llyiahf/vczjk/ld9;

    return-void
.end method


# virtual methods
.method public final OooO00o(IJ)Llyiahf/vczjk/ju4;
    .locals 6

    iget-object v1, p0, Llyiahf/vczjk/ku4;->OooO0OO:Llyiahf/vczjk/ed5;

    if-eqz v1, :cond_0

    new-instance v0, Llyiahf/vczjk/h37;

    iget-object v5, p0, Llyiahf/vczjk/ku4;->OooO0O0:Llyiahf/vczjk/ld9;

    move v2, p1

    move-wide v3, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/h37;-><init>(Llyiahf/vczjk/ed5;IJLlyiahf/vczjk/ld9;)V

    iget-object p1, v1, Llyiahf/vczjk/ed5;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/i37;

    invoke-interface {p1, v0}, Llyiahf/vczjk/i37;->OooO0Oo(Llyiahf/vczjk/h37;)V

    return-object v0

    :cond_0
    sget-object p1, Llyiahf/vczjk/rj2;->OooO00o:Llyiahf/vczjk/rj2;

    return-object p1
.end method
