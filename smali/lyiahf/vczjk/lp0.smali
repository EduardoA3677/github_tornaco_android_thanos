.class public final Llyiahf/vczjk/lp0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/s83;


# static fields
.field public static final OooO00o:Llyiahf/vczjk/lp0;

.field public static OooO0O0:Ljava/lang/Boolean;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/lp0;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/lp0;->OooO00o:Llyiahf/vczjk/lp0;

    return-void
.end method


# virtual methods
.method public final OooO00o()Z
    .locals 1

    sget-object v0, Llyiahf/vczjk/lp0;->OooO0O0:Ljava/lang/Boolean;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0

    :cond_0
    const-string v0, "canFocus is read before it is written"

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object v0

    throw v0
.end method

.method public final OooO0Oo(Z)V
    .locals 0

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    sput-object p1, Llyiahf/vczjk/lp0;->OooO0O0:Ljava/lang/Boolean;

    return-void
.end method
