.class public abstract Llyiahf/vczjk/cb9;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/hc3;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/hc3;

    const-string v1, "kotlin.suspend"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/cb9;->OooO00o:Llyiahf/vczjk/hc3;

    new-instance v0, Llyiahf/vczjk/do0;

    sget-object v1, Llyiahf/vczjk/x09;->OooOO0o:Llyiahf/vczjk/hc3;

    const-string v2, "suspend"

    invoke-static {v2}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/do0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    return-void
.end method
