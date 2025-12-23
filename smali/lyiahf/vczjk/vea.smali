.class public final Llyiahf/vczjk/vea;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/wea;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wea;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vea;->this$0:Llyiahf/vczjk/wea;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/vea;->this$0:Llyiahf/vczjk/wea;

    iget v0, v0, Llyiahf/vczjk/wea;->OooOOO0:I

    int-to-long v0, v0

    invoke-static {v0, v1}, Ljava/math/BigInteger;->valueOf(J)Ljava/math/BigInteger;

    move-result-object v0

    const/16 v1, 0x20

    invoke-virtual {v0, v1}, Ljava/math/BigInteger;->shiftLeft(I)Ljava/math/BigInteger;

    move-result-object v0

    iget-object v2, p0, Llyiahf/vczjk/vea;->this$0:Llyiahf/vczjk/wea;

    iget v2, v2, Llyiahf/vczjk/wea;->OooOOO:I

    int-to-long v2, v2

    invoke-static {v2, v3}, Ljava/math/BigInteger;->valueOf(J)Ljava/math/BigInteger;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/math/BigInteger;->or(Ljava/math/BigInteger;)Ljava/math/BigInteger;

    move-result-object v0

    invoke-virtual {v0, v1}, Ljava/math/BigInteger;->shiftLeft(I)Ljava/math/BigInteger;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/vea;->this$0:Llyiahf/vczjk/wea;

    iget v1, v1, Llyiahf/vczjk/wea;->OooOOOO:I

    int-to-long v1, v1

    invoke-static {v1, v2}, Ljava/math/BigInteger;->valueOf(J)Ljava/math/BigInteger;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/math/BigInteger;->or(Ljava/math/BigInteger;)Ljava/math/BigInteger;

    move-result-object v0

    return-object v0
.end method
