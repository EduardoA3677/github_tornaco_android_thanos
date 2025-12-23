.class public final Llyiahf/vczjk/xv7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/z70;
.implements Llyiahf/vczjk/fm1;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/v85;

.field public final OooO0O0:Llyiahf/vczjk/d80;

.field public OooO0OO:Llyiahf/vczjk/wj8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v85;Llyiahf/vczjk/f80;Llyiahf/vczjk/wv7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xv7;->OooO00o:Llyiahf/vczjk/v85;

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p1, p3, Llyiahf/vczjk/wv7;->OooO00o:Llyiahf/vczjk/ii;

    invoke-virtual {p1}, Llyiahf/vczjk/ii;->o0000oo()Llyiahf/vczjk/w23;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/xv7;->OooO0O0:Llyiahf/vczjk/d80;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/f80;->OooO0o0(Llyiahf/vczjk/d80;)V

    invoke-virtual {p1, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    return-void
.end method

.method public static OooO0OO(II)I
    .locals 2

    div-int v0, p0, p1

    xor-int v1, p0, p1

    if-gez v1, :cond_0

    mul-int v1, v0, p1

    if-eq v1, p0, :cond_0

    add-int/lit8 v0, v0, -0x1

    :cond_0
    mul-int/2addr v0, p1

    sub-int/2addr p0, v0

    return p0
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xv7;->OooO00o:Llyiahf/vczjk/v85;

    invoke-virtual {v0}, Llyiahf/vczjk/v85;->invalidateSelf()V

    return-void
.end method

.method public final OooO0O0(Ljava/util/List;Ljava/util/List;)V
    .locals 0

    return-void
.end method
