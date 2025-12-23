.class public final Llyiahf/vczjk/ur8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ir8;

.field public final synthetic OooOOO0:Llyiahf/vczjk/rr5;

.field public final synthetic OooOOOO:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rr5;Llyiahf/vczjk/ir8;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ur8;->OooOOO0:Llyiahf/vczjk/rr5;

    iput-object p2, p0, Llyiahf/vczjk/ur8;->OooOOO:Llyiahf/vczjk/ir8;

    iput-boolean p3, p0, Llyiahf/vczjk/ur8;->OooOOOO:Z

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/cs8;

    move-object v7, p2

    check-cast v7, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    sget-object v0, Llyiahf/vczjk/pr8;->OooO00o:Llyiahf/vczjk/pr8;

    iget-object v3, p0, Llyiahf/vczjk/ur8;->OooOOO:Llyiahf/vczjk/ir8;

    const/high16 v8, 0x30000

    iget-object v1, p0, Llyiahf/vczjk/ur8;->OooOOO0:Llyiahf/vczjk/rr5;

    const/4 v2, 0x0

    iget-boolean v4, p0, Llyiahf/vczjk/ur8;->OooOOOO:Z

    const-wide/16 v5, 0x0

    invoke-virtual/range {v0 .. v8}, Llyiahf/vczjk/pr8;->OooO00o(Llyiahf/vczjk/rr5;Llyiahf/vczjk/hl5;Llyiahf/vczjk/ir8;ZJLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
