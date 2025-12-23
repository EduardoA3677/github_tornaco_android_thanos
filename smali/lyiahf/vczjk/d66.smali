.class public final Llyiahf/vczjk/d66;
.super Llyiahf/vczjk/z56;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/d66;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/d66;

    sget-object v1, Llyiahf/vczjk/db4;->OooOOO0:Llyiahf/vczjk/db4;

    const-string v2, "number"

    const-class v3, Ljava/lang/Short;

    invoke-direct {v0, v3, v1, v2}, Llyiahf/vczjk/z56;-><init>(Ljava/lang/Class;Llyiahf/vczjk/db4;Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/d66;->OooOOOO:Llyiahf/vczjk/d66;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 0

    check-cast p1, Ljava/lang/Short;

    invoke-virtual {p1}, Ljava/lang/Short;->shortValue()S

    move-result p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000O(S)V

    return-void
.end method
