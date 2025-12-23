.class public final Llyiahf/vczjk/c66;
.super Llyiahf/vczjk/z56;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/c66;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/c66;

    sget-object v1, Llyiahf/vczjk/db4;->OooOOO0:Llyiahf/vczjk/db4;

    const-string v2, "integer"

    const-class v3, Ljava/lang/Number;

    invoke-direct {v0, v3, v1, v2}, Llyiahf/vczjk/z56;-><init>(Ljava/lang/Class;Llyiahf/vczjk/db4;Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/c66;->OooOOOO:Llyiahf/vczjk/c66;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 0

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000oo(I)V

    return-void
.end method
