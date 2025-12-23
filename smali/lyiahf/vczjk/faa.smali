.class public final Llyiahf/vczjk/faa;
.super Llyiahf/vczjk/m49;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nr7;
.implements Llyiahf/vczjk/wo1;


# static fields
.field public static final OooOOOO:[Ljava/lang/Object;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected _listDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected _listType:Llyiahf/vczjk/x64;

.field protected _mapDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected _mapType:Llyiahf/vczjk/x64;

.field protected final _nonMerging:Z

.field protected _numberDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected _stringDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    sput-object v0, Llyiahf/vczjk/faa;->OooOOOO:[Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/faa;Z)V
    .locals 1

    const-class v0, Ljava/lang/Object;

    invoke-direct {p0, v0}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    iget-object v0, p1, Llyiahf/vczjk/faa;->_mapDeserializer:Llyiahf/vczjk/e94;

    iput-object v0, p0, Llyiahf/vczjk/faa;->_mapDeserializer:Llyiahf/vczjk/e94;

    iget-object v0, p1, Llyiahf/vczjk/faa;->_listDeserializer:Llyiahf/vczjk/e94;

    iput-object v0, p0, Llyiahf/vczjk/faa;->_listDeserializer:Llyiahf/vczjk/e94;

    iget-object v0, p1, Llyiahf/vczjk/faa;->_stringDeserializer:Llyiahf/vczjk/e94;

    iput-object v0, p0, Llyiahf/vczjk/faa;->_stringDeserializer:Llyiahf/vczjk/e94;

    iget-object v0, p1, Llyiahf/vczjk/faa;->_numberDeserializer:Llyiahf/vczjk/e94;

    iput-object v0, p0, Llyiahf/vczjk/faa;->_numberDeserializer:Llyiahf/vczjk/e94;

    iget-object v0, p1, Llyiahf/vczjk/faa;->_listType:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/faa;->_listType:Llyiahf/vczjk/x64;

    iget-object p1, p1, Llyiahf/vczjk/faa;->_mapType:Llyiahf/vczjk/x64;

    iput-object p1, p0, Llyiahf/vczjk/faa;->_mapType:Llyiahf/vczjk/x64;

    iput-boolean p2, p0, Llyiahf/vczjk/faa;->_nonMerging:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;)V
    .locals 1

    const-class v0, Ljava/lang/Object;

    invoke-direct {p0, v0}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    iput-object p1, p0, Llyiahf/vczjk/faa;->_listType:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/faa;->_mapType:Llyiahf/vczjk/x64;

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/faa;->_nonMerging:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/v72;)V
    .locals 6

    const-class v0, Ljava/lang/Object;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->Oooooo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v0

    const-class v1, Ljava/lang/String;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/v72;->Oooooo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-result-object v2

    iget-object v3, p0, Llyiahf/vczjk/faa;->_listType:Llyiahf/vczjk/x64;

    const/4 v4, 0x0

    if-nez v3, :cond_1

    const-class v3, Ljava/util/List;

    invoke-virtual {v2, v3, v0}, Llyiahf/vczjk/a4a;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/a21;

    move-result-object v3

    invoke-virtual {p1, v3}, Llyiahf/vczjk/v72;->o00Oo0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/vy0;->OooOOoo(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_0

    move-object v3, v4

    :cond_0
    iput-object v3, p0, Llyiahf/vczjk/faa;->_listDeserializer:Llyiahf/vczjk/e94;

    goto :goto_0

    :cond_1
    invoke-virtual {p1, v3}, Llyiahf/vczjk/v72;->o00Oo0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v3

    iput-object v3, p0, Llyiahf/vczjk/faa;->_listDeserializer:Llyiahf/vczjk/e94;

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/faa;->_mapType:Llyiahf/vczjk/x64;

    if-nez v3, :cond_3

    const-class v3, Ljava/util/Map;

    invoke-virtual {v2, v3, v1, v0}, Llyiahf/vczjk/a4a;->OooO(Ljava/lang/Class;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;)Llyiahf/vczjk/wb5;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o00Oo0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooOOoo(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_2

    move-object v0, v4

    :cond_2
    iput-object v0, p0, Llyiahf/vczjk/faa;->_mapDeserializer:Llyiahf/vczjk/e94;

    goto :goto_1

    :cond_3
    invoke-virtual {p1, v3}, Llyiahf/vczjk/v72;->o00Oo0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/faa;->_mapDeserializer:Llyiahf/vczjk/e94;

    :goto_1
    invoke-virtual {p1, v1}, Llyiahf/vczjk/v72;->o00Oo0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooOOoo(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_4

    move-object v0, v4

    :cond_4
    iput-object v0, p0, Llyiahf/vczjk/faa;->_stringDeserializer:Llyiahf/vczjk/e94;

    const-class v0, Ljava/lang/Number;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/a4a;->OooOO0O(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o00Oo0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooOOoo(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_5

    move-object v0, v4

    :cond_5
    iput-object v0, p0, Llyiahf/vczjk/faa;->_numberDeserializer:Llyiahf/vczjk/e94;

    invoke-static {}, Llyiahf/vczjk/a4a;->OooOOOo()Llyiahf/vczjk/ep8;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/faa;->_mapDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {p1, v1, v4, v0}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/faa;->_mapDeserializer:Llyiahf/vczjk/e94;

    iget-object v1, p0, Llyiahf/vczjk/faa;->_listDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {p1, v1, v4, v0}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/faa;->_listDeserializer:Llyiahf/vczjk/e94;

    iget-object v1, p0, Llyiahf/vczjk/faa;->_stringDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {p1, v1, v4, v0}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/faa;->_stringDeserializer:Llyiahf/vczjk/e94;

    iget-object v1, p0, Llyiahf/vczjk/faa;->_numberDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {p1, v1, v4, v0}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/faa;->_numberDeserializer:Llyiahf/vczjk/e94;

    return-void
.end method

.method public final OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;
    .locals 3

    const/4 v0, 0x1

    if-nez p2, :cond_1

    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object p1

    iget-object v1, p1, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    iget-object v1, v1, Llyiahf/vczjk/vh1;->_overrides:Ljava/util/Map;

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    const-class v2, Ljava/lang/Object;

    invoke-interface {v1, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/uh1;

    :goto_0
    iget-object p1, p1, Llyiahf/vczjk/fc5;->_configOverrides:Llyiahf/vczjk/vh1;

    iget-object p1, p1, Llyiahf/vczjk/vh1;->_defaultMergeable:Ljava/lang/Boolean;

    invoke-virtual {p2, p1}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    move p1, v0

    goto :goto_1

    :cond_1
    const/4 p1, 0x0

    :goto_1
    iget-object p2, p0, Llyiahf/vczjk/faa;->_stringDeserializer:Llyiahf/vczjk/e94;

    if-nez p2, :cond_3

    iget-object p2, p0, Llyiahf/vczjk/faa;->_numberDeserializer:Llyiahf/vczjk/e94;

    if-nez p2, :cond_3

    iget-object p2, p0, Llyiahf/vczjk/faa;->_mapDeserializer:Llyiahf/vczjk/e94;

    if-nez p2, :cond_3

    iget-object p2, p0, Llyiahf/vczjk/faa;->_listDeserializer:Llyiahf/vczjk/e94;

    if-nez p2, :cond_3

    if-eqz p1, :cond_2

    new-instance p1, Llyiahf/vczjk/eaa;

    invoke-direct {p1, v0}, Llyiahf/vczjk/eaa;-><init>(Z)V

    return-object p1

    :cond_2
    sget-object p1, Llyiahf/vczjk/eaa;->OooOOOO:Llyiahf/vczjk/eaa;

    return-object p1

    :cond_3
    iget-boolean p2, p0, Llyiahf/vczjk/faa;->_nonMerging:Z

    if-eq p1, p2, :cond_4

    new-instance p2, Llyiahf/vczjk/faa;

    invoke-direct {p2, p0, p1}, Llyiahf/vczjk/faa;-><init>(Llyiahf/vczjk/faa;Z)V

    return-object p2

    :cond_4
    return-object p0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0OoOo0()I

    move-result v0

    const/4 v1, 0x0

    packed-switch v0, :pswitch_data_0

    :pswitch_0
    const-class v0, Ljava/lang/Object;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v1

    :pswitch_1
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o000OOo()Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_2
    return-object v1

    :pswitch_3
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_4
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_5
    iget-object v0, p0, Llyiahf/vczjk/faa;->_numberDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    sget-object v0, Llyiahf/vczjk/w72;->OooOOO0:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p1

    if-eqz p1, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00oO0o()Ljava/math/BigDecimal;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000oo()Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :pswitch_6
    iget-object v0, p0, Llyiahf/vczjk/faa;->_numberDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_2

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_2
    sget v0, Llyiahf/vczjk/m49;->OooOOO0:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o00000oO(I)Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-static {p1, p2}, Llyiahf/vczjk/m49;->OooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :cond_3
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00000oo()Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :pswitch_7
    iget-object v0, p0, Llyiahf/vczjk/faa;->_stringDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_4

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_4
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_8
    sget-object v0, Llyiahf/vczjk/w72;->OooOOOo:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/faa;->OoooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)[Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_5
    iget-object v0, p0, Llyiahf/vczjk/faa;->_listDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_6

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_6
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/faa;->OoooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_9
    iget-object v0, p0, Llyiahf/vczjk/faa;->_mapDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_7

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_7
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/faa;->OoooOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_9
        :pswitch_9
        :pswitch_8
        :pswitch_0
        :pswitch_9
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0OoOo0()I

    move-result v0

    const/4 v1, 0x1

    if-eq v0, v1, :cond_5

    const/4 v1, 0x3

    if-eq v0, v1, :cond_5

    const/4 v1, 0x0

    packed-switch v0, :pswitch_data_0

    const-class p3, Ljava/lang/Object;

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v1

    :pswitch_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o000OOo()Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_1
    return-object v1

    :pswitch_2
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_3
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_4
    iget-object p3, p0, Llyiahf/vczjk/faa;->_numberDeserializer:Llyiahf/vczjk/e94;

    if-eqz p3, :cond_0

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    sget-object p3, Llyiahf/vczjk/w72;->OooOOO0:Llyiahf/vczjk/w72;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p2

    if-eqz p2, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00oO0o()Ljava/math/BigDecimal;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00000oo()Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :pswitch_5
    iget-object p3, p0, Llyiahf/vczjk/faa;->_numberDeserializer:Llyiahf/vczjk/e94;

    if-eqz p3, :cond_2

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_2
    sget p3, Llyiahf/vczjk/m49;->OooOOO0:I

    invoke-virtual {p2, p3}, Llyiahf/vczjk/v72;->o00000oO(I)Z

    move-result p3

    if-eqz p3, :cond_3

    invoke-static {p2, p1}, Llyiahf/vczjk/m49;->OooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00000oo()Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :pswitch_6
    iget-object p3, p0, Llyiahf/vczjk/faa;->_stringDeserializer:Llyiahf/vczjk/e94;

    if-eqz p3, :cond_4

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_5
    :pswitch_7
    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0O0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x5
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/faa;->_nonMerging:Z

    if-eqz v0, :cond_0

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/faa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0OoOo0()I

    move-result v0

    packed-switch v0, :pswitch_data_0

    :pswitch_0
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/faa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_1
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o000OOo()Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_2
    const/4 p1, 0x0

    return-object p1

    :pswitch_3
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_4
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_5
    iget-object v0, p0, Llyiahf/vczjk/faa;->_numberDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_1
    sget-object p3, Llyiahf/vczjk/w72;->OooOOO0:Llyiahf/vczjk/w72;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p2

    if-eqz p2, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00oO0o()Ljava/math/BigDecimal;

    move-result-object p1

    return-object p1

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00000oo()Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :pswitch_6
    iget-object v0, p0, Llyiahf/vczjk/faa;->_numberDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_3

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_3
    sget p3, Llyiahf/vczjk/m49;->OooOOO0:I

    invoke-virtual {p2, p3}, Llyiahf/vczjk/v72;->o00000oO(I)Z

    move-result p3

    if-eqz p3, :cond_4

    invoke-static {p2, p1}, Llyiahf/vczjk/m49;->OooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00000oo()Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :pswitch_7
    iget-object v0, p0, Llyiahf/vczjk/faa;->_stringDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_5

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_8
    iget-object v0, p0, Llyiahf/vczjk/faa;->_listDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_6

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_6
    instance-of v0, p3, Ljava/util/Collection;

    if-eqz v0, :cond_8

    check-cast p3, Ljava/util/Collection;

    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-eq v0, v1, :cond_7

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/faa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v0

    invoke-interface {p3, v0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_7
    return-object p3

    :cond_8
    sget-object p3, Llyiahf/vczjk/w72;->OooOOOo:Llyiahf/vczjk/w72;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p3

    if-eqz p3, :cond_9

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/faa;->OoooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)[Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_9
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/faa;->OoooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_9
    iget-object v0, p0, Llyiahf/vczjk/faa;->_mapDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_a

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_a
    instance-of v0, p3, Ljava/util/Map;

    if-eqz v0, :cond_10

    check-cast p3, Ljava/util/Map;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_b

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    :cond_b
    sget-object v1, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_c

    goto :goto_2

    :cond_c
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v0

    :cond_d
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-interface {p3, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_e

    invoke-virtual {p0, p1, p2, v1}, Llyiahf/vczjk/faa;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    goto :goto_1

    :cond_e
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/faa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v2

    :goto_1
    if-eq v2, v1, :cond_f

    invoke-interface {p3, v0, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_f
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_d

    :goto_2
    return-object p3

    :cond_10
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/faa;->OoooOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_9
        :pswitch_9
        :pswitch_8
        :pswitch_0
        :pswitch_9
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public final OooOOO()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public final OoooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 8

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    const/4 v2, 0x2

    if-ne v0, v1, :cond_0

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1, v2}, Ljava/util/ArrayList;-><init>(I)V

    return-object p1

    :cond_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/faa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v3

    if-ne v3, v1, :cond_1

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-object p1

    :cond_1
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/faa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v3

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v4

    if-ne v4, v1, :cond_2

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {p1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-object p1

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0000oO()Llyiahf/vczjk/ie;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/ie;->OooOO0o()[Ljava/lang/Object;

    move-result-object v4

    const/4 v5, 0x0

    aput-object v0, v4, v5

    const/4 v0, 0x1

    aput-object v3, v4, v0

    move v3, v2

    :goto_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/faa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v6

    add-int/2addr v2, v0

    array-length v7, v4

    if-lt v3, v7, :cond_3

    invoke-virtual {v1, v4}, Llyiahf/vczjk/ie;->OooO0o0([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    move v3, v5

    :cond_3
    add-int/lit8 v7, v3, 0x1

    aput-object v6, v4, v3

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v3

    sget-object v6, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v3, v6, :cond_4

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v1, v4, v7, p1}, Llyiahf/vczjk/ie;->OooO0o([Ljava/lang/Object;ILjava/util/ArrayList;)V

    return-object p1

    :cond_4
    move v3, v7

    goto :goto_0
.end method

.method public final OoooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)[Ljava/lang/Object;
    .locals 6

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    sget-object p1, Llyiahf/vczjk/faa;->OooOOOO:[Ljava/lang/Object;

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0000oO()Llyiahf/vczjk/ie;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ie;->OooOO0o()[Ljava/lang/Object;

    move-result-object v1

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/faa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v4

    array-length v5, v1

    if-lt v3, v5, :cond_1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ie;->OooO0o0([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v1

    move v3, v2

    :cond_1
    add-int/lit8 v5, v3, 0x1

    aput-object v4, v1, v3

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v3, v4, :cond_2

    invoke-virtual {v0, v5, v1}, Llyiahf/vczjk/ie;->OooO0oO(I[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_2
    move v3, v5

    goto :goto_0
.end method

.method public final OoooOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 6

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v0

    goto :goto_0

    :cond_0
    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v0

    goto :goto_0

    :cond_1
    sget-object v1, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    const/4 v2, 0x0

    if-ne v0, v1, :cond_6

    move-object v0, v2

    :goto_0
    const/4 v1, 0x2

    if-nez v0, :cond_2

    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1, v1}, Ljava/util/LinkedHashMap;-><init>(I)V

    return-object p1

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/faa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v3

    if-nez v3, :cond_3

    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1, v1}, Ljava/util/LinkedHashMap;-><init>(I)V

    invoke-virtual {p1, v0, v2}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object p1

    :cond_3
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/faa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v4

    if-nez v4, :cond_4

    new-instance p1, Ljava/util/LinkedHashMap;

    const/4 p2, 0x4

    invoke-direct {p1, p2}, Ljava/util/LinkedHashMap;-><init>(I)V

    invoke-virtual {p1, v0, v2}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p1, v3, v1}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object p1

    :cond_4
    new-instance v5, Ljava/util/LinkedHashMap;

    invoke-direct {v5}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-virtual {v5, v0, v2}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v5, v3, v1}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_5
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/faa;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {v5, v4, v0}, Ljava/util/AbstractMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v4

    if-nez v4, :cond_5

    return-object v5

    :cond_6
    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v2
.end method
