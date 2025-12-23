.class public final synthetic Llyiahf/vczjk/cz0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:J

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:Llyiahf/vczjk/oe3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/oe3;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cz0;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-wide p2, p0, Llyiahf/vczjk/cz0;->OooOOO:J

    iput-object p4, p0, Llyiahf/vczjk/cz0;->OooOOOO:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p1, 0x187

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-wide v1, p0, Llyiahf/vczjk/cz0;->OooOOO:J

    iget-object v3, p0, Llyiahf/vczjk/cz0;->OooOOOO:Llyiahf/vczjk/oe3;

    iget-object v0, p0, Llyiahf/vczjk/cz0;->OooOOO0:Llyiahf/vczjk/kl5;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/l4a;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
