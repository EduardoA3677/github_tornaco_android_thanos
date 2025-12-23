.class public final Llyiahf/vczjk/ez0;
.super Llyiahf/vczjk/wr6;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0oO:Llyiahf/vczjk/fz0;

.field public final synthetic OooO0oo:Llyiahf/vczjk/i5a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fz0;Llyiahf/vczjk/i5a;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ez0;->OooO0oO:Llyiahf/vczjk/fz0;

    iput-object p2, p0, Llyiahf/vczjk/ez0;->OooO0oo:Llyiahf/vczjk/i5a;

    return-void
.end method


# virtual methods
.method public final OooOo(Llyiahf/vczjk/l3a;Llyiahf/vczjk/yk4;)Llyiahf/vczjk/pt7;
    .locals 2

    const-string v0, "state"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "type"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/ez0;->OooO0oO:Llyiahf/vczjk/fz0;

    invoke-interface {p1, p2}, Llyiahf/vczjk/fz0;->o00Ooo(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/dp8;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    iget-object v1, p0, Llyiahf/vczjk/ez0;->OooO0oo:Llyiahf/vczjk/i5a;

    invoke-virtual {v1, p2, v0}, Llyiahf/vczjk/i5a;->OooO0oO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object p2

    invoke-interface {p1, p2}, Llyiahf/vczjk/fz0;->o000000(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object p1
.end method
