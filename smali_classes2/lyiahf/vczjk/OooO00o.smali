.class public abstract Llyiahf/vczjk/OooO00o;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:[B


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/jm0;->OooOOOO:Llyiahf/vczjk/jm0;

    const-string v0, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    invoke-static {v0}, Llyiahf/vczjk/ws7;->OooO(Ljava/lang/String;)Llyiahf/vczjk/jm0;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/jm0;->OooO0Oo()[B

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/OooO00o;->OooO00o:[B

    const-string v0, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    invoke-static {v0}, Llyiahf/vczjk/ws7;->OooO(Ljava/lang/String;)Llyiahf/vczjk/jm0;

    return-void
.end method
