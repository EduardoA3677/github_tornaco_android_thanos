.class public final Llyiahf/vczjk/ja3;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0OO:Llyiahf/vczjk/ia3;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/uqa;

.field public final OooO0O0:Llyiahf/vczjk/to1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/e86;->OooOOOO:Llyiahf/vczjk/e86;

    new-instance v1, Llyiahf/vczjk/ia3;

    invoke-direct {v1, v0}, Llyiahf/vczjk/o000O0o;-><init>(Llyiahf/vczjk/nr1;)V

    sput-object v1, Llyiahf/vczjk/ja3;->OooO0OO:Llyiahf/vczjk/ia3;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/uqa;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ja3;->OooO00o:Llyiahf/vczjk/uqa;

    sget-object p1, Llyiahf/vczjk/jc2;->OooO00o:Llyiahf/vczjk/xl3;

    sget-object v1, Llyiahf/vczjk/ja3;->OooO0OO:Llyiahf/vczjk/ia3;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1, p1}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    invoke-interface {p1, v0}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/u99;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/x74;-><init>(Llyiahf/vczjk/v74;)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ja3;->OooO0O0:Llyiahf/vczjk/to1;

    return-void
.end method
