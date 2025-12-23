.class public final Llyiahf/vczjk/o93;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/c0a;


# static fields
.field public static final OooOoo0:Llyiahf/vczjk/uk2;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/ga8;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/uk2;

    const/16 v1, 0x11

    invoke-direct {v0, v1}, Llyiahf/vczjk/uk2;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/o93;->OooOoo0:Llyiahf/vczjk/uk2;

    return-void
.end method


# virtual methods
.method public final OooOO0O()Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/o93;->OooOoo0:Llyiahf/vczjk/uk2;

    return-object v0
.end method

.method public final o00000OO(Llyiahf/vczjk/xn4;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o93;->OooOoOO:Llyiahf/vczjk/ga8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ga8;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-static {p0}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/o93;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/o93;->o00000OO(Llyiahf/vczjk/xn4;)V

    :cond_0
    return-void
.end method
