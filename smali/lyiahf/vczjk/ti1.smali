.class public abstract Llyiahf/vczjk/ti1;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/or5;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    sget-object v0, Llyiahf/vczjk/e31;->OooO0o0:Llyiahf/vczjk/ot7;

    iget v1, v0, Llyiahf/vczjk/a31;->OooO0OO:I

    shl-int/lit8 v2, v1, 0x6

    or-int/2addr v1, v2

    new-instance v2, Llyiahf/vczjk/qi1;

    const/4 v3, 0x1

    invoke-direct {v2, v0, v0, v3}, Llyiahf/vczjk/si1;-><init>(Llyiahf/vczjk/a31;Llyiahf/vczjk/a31;I)V

    sget-object v3, Llyiahf/vczjk/e31;->OooOo:Llyiahf/vczjk/t96;

    iget v4, v3, Llyiahf/vczjk/a31;->OooO0OO:I

    shl-int/lit8 v4, v4, 0x6

    iget v5, v0, Llyiahf/vczjk/a31;->OooO0OO:I

    or-int/2addr v4, v5

    new-instance v6, Llyiahf/vczjk/si1;

    const/4 v7, 0x0

    invoke-direct {v6, v0, v3, v7}, Llyiahf/vczjk/si1;-><init>(Llyiahf/vczjk/a31;Llyiahf/vczjk/a31;I)V

    shl-int/lit8 v5, v5, 0x6

    iget v8, v3, Llyiahf/vczjk/a31;->OooO0OO:I

    or-int/2addr v5, v8

    new-instance v8, Llyiahf/vczjk/si1;

    invoke-direct {v8, v3, v0, v7}, Llyiahf/vczjk/si1;-><init>(Llyiahf/vczjk/a31;Llyiahf/vczjk/a31;I)V

    sget-object v0, Llyiahf/vczjk/t14;->OooO00o:Llyiahf/vczjk/or5;

    new-instance v0, Llyiahf/vczjk/or5;

    invoke-direct {v0}, Llyiahf/vczjk/or5;-><init>()V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/or5;->OooO0oo(ILjava/lang/Object;)V

    invoke-virtual {v0, v4, v6}, Llyiahf/vczjk/or5;->OooO0oo(ILjava/lang/Object;)V

    invoke-virtual {v0, v5, v8}, Llyiahf/vczjk/or5;->OooO0oo(ILjava/lang/Object;)V

    sput-object v0, Llyiahf/vczjk/ti1;->OooO00o:Llyiahf/vczjk/or5;

    return-void
.end method
