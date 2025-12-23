.class public final Llyiahf/vczjk/w05;
.super Llyiahf/vczjk/o0OOO0o;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/u05;

.field public OooO0O0:Z

.field public OooO0OO:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/u05;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/w05;->OooO00o:Llyiahf/vczjk/u05;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/gd0;)Z
    .locals 2

    instance-of p1, p1, Llyiahf/vczjk/c15;

    const/4 v0, 0x0

    if-eqz p1, :cond_1

    iget-boolean p1, p0, Llyiahf/vczjk/w05;->OooO0O0:Z

    const/4 v1, 0x1

    if-eqz p1, :cond_0

    iget p1, p0, Llyiahf/vczjk/w05;->OooO0OO:I

    if-ne p1, v1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/w05;->OooO00o:Llyiahf/vczjk/u05;

    iput-boolean v0, p1, Llyiahf/vczjk/u05;->OooO0oO:Z

    iput-boolean v0, p0, Llyiahf/vczjk/w05;->OooO0O0:Z

    :cond_0
    return v1

    :cond_1
    return v0
.end method

.method public final OooO0o()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/gd0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/w05;->OooO00o:Llyiahf/vczjk/u05;

    return-object v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/md2;)Llyiahf/vczjk/hd0;
    .locals 2

    iget-boolean v0, p1, Llyiahf/vczjk/md2;->OooO0oo:Z

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    iput-boolean v1, p0, Llyiahf/vczjk/w05;->OooO0O0:Z

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/w05;->OooO0OO:I

    goto :goto_0

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/w05;->OooO0O0:Z

    if-eqz v0, :cond_1

    iget v0, p0, Llyiahf/vczjk/w05;->OooO0OO:I

    add-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/w05;->OooO0OO:I

    :cond_1
    :goto_0
    iget p1, p1, Llyiahf/vczjk/md2;->OooO0O0:I

    invoke-static {p1}, Llyiahf/vczjk/hd0;->OooO00o(I)Llyiahf/vczjk/hd0;

    move-result-object p1

    return-object p1
.end method
