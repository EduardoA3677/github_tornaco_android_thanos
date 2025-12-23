.class public final Llyiahf/vczjk/em2;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:I

.field public final OooO0O0:Llyiahf/vczjk/xi5;

.field public OooO0OO:Llyiahf/vczjk/xi5;

.field public OooO0Oo:Llyiahf/vczjk/xi5;

.field public OooO0o:I

.field public OooO0o0:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xi5;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/em2;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/em2;->OooO0O0:Llyiahf/vczjk/xi5;

    iput-object p1, p0, Llyiahf/vczjk/em2;->OooO0OO:Llyiahf/vczjk/xi5;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/em2;->OooO00o:I

    iget-object v0, p0, Llyiahf/vczjk/em2;->OooO0O0:Llyiahf/vczjk/xi5;

    iput-object v0, p0, Llyiahf/vczjk/em2;->OooO0OO:Llyiahf/vczjk/xi5;

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/em2;->OooO0o:I

    return-void
.end method

.method public final OooO0O0()Z
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/em2;->OooO0OO:Llyiahf/vczjk/xi5;

    iget-object v0, v0, Llyiahf/vczjk/xi5;->OooO0O0:Llyiahf/vczjk/a6a;

    invoke-virtual {v0}, Llyiahf/vczjk/a6a;->OooO0O0()Llyiahf/vczjk/vi5;

    move-result-object v0

    const/4 v1, 0x6

    invoke-virtual {v0, v1}, Llyiahf/vczjk/db5;->OooO00o(I)I

    move-result v1

    const/4 v2, 0x1

    if-eqz v1, :cond_0

    iget-object v3, v0, Llyiahf/vczjk/db5;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Ljava/nio/ByteBuffer;

    iget v0, v0, Llyiahf/vczjk/db5;->OooOOO0:I

    add-int/2addr v1, v0

    invoke-virtual {v3, v1}, Ljava/nio/ByteBuffer;->get(I)B

    move-result v0

    if-eqz v0, :cond_0

    return v2

    :cond_0
    iget v0, p0, Llyiahf/vczjk/em2;->OooO0o0:I

    const v1, 0xfe0f

    if-ne v0, v1, :cond_1

    return v2

    :cond_1
    const/4 v0, 0x0

    return v0
.end method
